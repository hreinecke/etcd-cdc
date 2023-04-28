#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "nvmet_common.h"
#include "nvmet_tcp.h"

#define NVME_VER ((1 << 16) | (4 << 8)) /* NVMe 1.4 */

LIST_HEAD(ctrl_list);
pthread_mutex_t ctrl_mutex;

static int nvmf_ctrl_id = 1;

static int send_response(struct endpoint *ep, struct ep_qe *qe,
			 u16 status)
{
	int ret;

	set_response(&qe->resp, qe->ccid, status, true);
	ret = tcp_send_rsp(ep, &qe->resp);
	tcp_release_tag(ep, qe);
	return ret;
}

static int handle_property_set(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_property_set %x = %llx",
		   cmd->prop_set.offset, cmd->prop_set.value);
#endif
	if (cmd->prop_set.offset == NVME_REG_CC) {
		ep->ctrl->cc = le64toh(cmd->prop_set.value);
		if (ep->ctrl->cc & NVME_CC_SHN_MASK)
			ep->ctrl->csts = NVME_CSTS_SHST_CMPLT;
		else {
			if (ep->ctrl->cc & NVME_CC_ENABLE)
				ep->ctrl->csts = NVME_CSTS_RDY;
			else
				ep->ctrl->csts = NVME_CSTS_SHST_CMPLT;
		}
	} else
		ret = NVME_SC_INVALID_FIELD;

	return ret;
}

static int handle_property_get(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	u64 value;

	if (cmd->prop_get.offset == NVME_REG_CSTS)
		value = ep->ctrl->csts;
	else if (cmd->prop_get.offset == NVME_REG_CAP)
		value = 0x200f0003ffL;
	else if (cmd->prop_get.offset == NVME_REG_CC)
		value = ep->ctrl->cc;
	else if (cmd->prop_get.offset == NVME_REG_VS)
		value = NVME_VER;
	else {
#ifdef DEBUG_COMMANDS
		print_debug("nvme_fabrics_type_property_get %x: N/I",
			    cmd->prop_get.offset);
#endif
		return NVME_SC_INVALID_FIELD;
	}

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_property_get %x: %llx",
		    cmd->prop_get.offset, value);
#endif
	qe->resp.result.u64 = htole64(value);

	return 0;
}

static int handle_set_features(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	u32 cdw10 = le32toh(cmd->common.cdw10);
	u32 cdw11 = le32toh(cmd->common.cdw11);
	int fid = (cdw10 & 0xff), ncqr, nsqr;
	int ret = 0;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_set_features cdw10 %x fid %x",
		    cdw10, fid);
#endif

	switch (fid) {
	case NVME_FEAT_NUM_QUEUES:
		ncqr = (cdw11 >> 16) & 0xffff;
		nsqr = cdw11 & 0xffff;
		if (ncqr < ep->ctrl->max_endpoints) {
			ep->ctrl->max_endpoints = ncqr;
		}
		if (nsqr < ep->ctrl->max_endpoints) {
			ep->ctrl->max_endpoints = nsqr;
		}
		qe->resp.result.u32 = htole32(ep->ctrl->max_endpoints << 16 |
					      ep->ctrl->max_endpoints);
		break;
	case NVME_FEAT_ASYNC_EVENT:
		ep->ctrl->aen_mask = cdw11;
		break;
	case NVME_FEAT_KATO:
		/* cdw11 / kato is in msecs */
		ep->ctrl->kato = cdw11 / ep->kato_interval;
		break;
	default:
		ret = NVME_SC_FEATURE_NOT_CHANGEABLE;
	}
	return ret;
}

static int handle_connect(struct endpoint *ep, struct ep_qe *qe,
			  struct nvme_command *cmd)
{
	struct ctrl_conn *ctrl;
	struct nvmf_connect_data *connect = qe->data;
	u16 sqsize;
	u16 cntlid, qid;
	u32 kato;
	int ret;

	qid = le16toh(cmd->connect.qid);
	sqsize = le16toh(cmd->connect.sqsize);
	kato = le32toh(cmd->connect.kato);

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_connect qid %u sqsize %u kato %u",
		    qid, sqsize, kato);
#endif

	ret = tcp_recv_data(ep, connect, qe->data_len);
	if (ret) {
		ep_err(ep, "tcp_recv_data failed with error %d", errno);
		return ret;
	}

	cntlid = le16toh(connect->cntlid);

	if (qid == 0 && cntlid != 0xFFFF) {
		ep_err(ep, "bad controller id %x, expecting %x",
		       cntlid, 0xffff);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (!sqsize) {
		ep_err(ep, "cntlid %d qid %d invalid sqsize",
		       cntlid, qid);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (ep->ctrl) {
		ctrl_err(ep, "qid %d already connected", qid);
		return NVME_SC_CONNECT_CTRL_BUSY;
	}
	if (qid == 0) {
		ep->qsize = NVMF_SQ_DEPTH;
	} else if (endpoint_update_qdepth(ep, sqsize) < 0) {
		ep_err(ep, "qid %d failed to increase sqsize %d",
		       qid, sqsize);
		return NVME_SC_INTERNAL;
	}

	ep->qid = qid;

	if (strcmp(connect->subsysnqn, NVME_DISC_SUBSYS_NAME) &&
	    (!discovery_nqn || strcmp(connect->subsysnqn, discovery_nqn))) {
		ep_err(ep, "subsystem '%s' not found",
		       connect->subsysnqn);
		return NVME_SC_CONNECT_INVALID_HOST;
	}

	pthread_mutex_lock(&ctrl_mutex);
	list_for_each_entry(ctrl, &ctrl_list, node) {
		if (!strncmp(connect->hostnqn, ctrl->nqn, MAX_NQN_SIZE)) {
			if (qid == 0 || ctrl->cntlid != cntlid)
				continue;
			ep->ctrl = ctrl;
			ctrl->num_endpoints++;
			break;
		}
	}
	if (!ep->ctrl) {
		ep_info(ep, "Allocating new controller '%s'",
			connect->hostnqn);
		ctrl = malloc(sizeof(*ctrl));
		if (!ctrl) {
			ep_err(ep, "Out of memory allocating controller");
		} else {
			memset(ctrl, 0, sizeof(*ctrl));
			strncpy(ctrl->nqn, connect->hostnqn, MAX_NQN_SIZE);
			ctrl->max_endpoints = NVMF_NUM_QUEUES;
			ctrl->kato = kato / ep->kato_interval;
			ep->ctrl = ctrl;
			ctrl->num_endpoints = 1;
			ctrl->cntlid = nvmf_ctrl_id++;
			list_add(&ctrl->node, &ctrl_list);
		}
	}
	pthread_mutex_unlock(&ctrl_mutex);
	if (!ep->ctrl) {
		ep_err(ep, "bad controller id %x for queue %d, expecting %x",
		       cntlid, qid, ctrl->cntlid);
		ret = NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (!ret) {
		ctrl_info(ep, "connected");
		qe->resp.result.u16 = htole16(ep->ctrl->cntlid);
	}
	return ret;
}

void handle_disconnect(struct endpoint *ep, int shutdown)
{
	struct ctrl_conn *ctrl = ep->ctrl;

	tcp_destroy_endpoint(ep);

	ep->state = DISCONNECTED;

	if (ctrl) {
		pthread_mutex_lock(&ctrl_mutex);
		ctrl->num_endpoints--;
		ep->ctrl = NULL;
		if (!ctrl->num_endpoints) {
			printf("ctrl %d: deleting controller\n",
			       ctrl->cntlid);
			list_del(&ctrl->node);
			free(ctrl);
		}
		pthread_mutex_unlock(&ctrl_mutex);
	}
}

static int handle_identify_ctrl(struct endpoint *ep, u8 *id_buf, u64 len)
{
	struct nvme_id_ctrl id;

	memset(&id, 0, sizeof(id));

	memset(id.fr, ' ', sizeof(id.fr));
	strncpy((char *) id.fr, " ", sizeof(id.fr));

	id.mdts = 0;
	id.cmic = 3;
	id.cntlid = htole16(ep->ctrl->cntlid);
	id.ver = htole32(NVME_VER);
	id.lpa = (1 << 2);
	id.sgls = htole32(1 << 0) | htole32(1 << 2) | htole32(1 << 20);
	id.kas = ep->kato_interval / 100; /* KAS is in units of 100 msecs */

	id.cntrltype = ep->ctrl->ctrl_type;
	if (!discovery_nqn) {
		strcpy(id.subnqn, NVME_DISC_SUBSYS_NAME);
		id.maxcmd = htole16(NVMF_DQ_DEPTH);
	} else {
		strcpy(id.subnqn, discovery_nqn);
		id.maxcmd = htole16(ep->qsize);
	}

	if (len > sizeof(id))
		len = sizeof(id);

	memcpy(id_buf, &id, len);

	return len;
}

static int handle_identify(struct endpoint *ep, struct ep_qe *qe,
			   struct nvme_command *cmd)
{
	int cns = cmd->identify.cns;
#ifdef DEBUG_COMMANDS
	u16 cid = cmd->identify.command_id;
#endif
	int ret, id_len;

#ifdef DEBUG_COMMANDS
	print_debug("cid %#x nvme_fabrics_identify cns %d len %llu",
		    cid, cns, qe->data_len);
#endif

	switch (cns) {
	case NVME_ID_CNS_CTRL:
		id_len = handle_identify_ctrl(ep, qe->data, qe->data_len);
		break;
	default:
		ctrl_err(ep, "unexpected identify command cns %u", cns);
		return NVME_SC_BAD_ATTRIBUTES;
	}

	if (id_len < 0)
		return NVME_SC_INVALID_NS;

	qe->data_pos = 0;
	ret = tcp_send_data(ep, qe, id_len);
	if (ret)
		ctrl_err(ep, "tcp_send_data failed with %d", ret);
	return ret;
}

static int format_disc_log(void *data, u64 data_offset,
			   u64 data_len, struct endpoint *ep)
{
	u8 *log_buf;
	size_t log_len = data_len;

	log_buf = nvmet_etcd_disc_log(ep->ctx, ep->ctrl->nqn, &log_len);
	if (!log_buf)
		return 0;

	if (log_len > data_len)
		log_len = data_len;
	if (data_offset > log_len) {
		ctrl_err(ep, "invalid discovery log page offset %llu len %lu",
			 data_offset, log_len);
		free(log_buf);
		return 0;
	}
	memcpy(data, (u8 *)log_buf + data_offset, log_len);
	ctrl_info(ep, "Returning discovery log page offset %llu len %lu",
		  data_offset, log_len);
	free(log_buf);
	return data_len;
}

static int handle_get_log_page(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0, log_len;
	u64 offset = le64toh(cmd->get_log_page.lpo);

#ifdef DEBUG_COMMANDS
	print_debug("nvme_get_log_page opcode %02x lid %02x offset %lu len %lu",
		    cmd->get_log_page.opcode, cmd->get_log_page.lid,
		    (unsigned long)offset, (unsigned long)qe->data_len);
#endif
	qe->data_pos = offset;

	switch (cmd->get_log_page.lid) {
	case 0x02:
		/* SMART Log */
		log_len = qe->data_len;
		memset(qe->data, 0, log_len);
		break;
	case 0x70:
		/* Discovery log */
		log_len = format_disc_log(qe->data, qe->data_pos,
					  qe->data_len, ep);
		if (!log_len) {
			ctrl_err(ep, "get_log_page: discovery log failed");
			return NVME_SC_INTERNAL;
		}
		break;
	default:
		ctrl_err(ep, "get_log_page: lid %02x not supported",
			cmd->get_log_page.lid);
		return NVME_SC_INVALID_FIELD;
	}
	ret = tcp_send_data(ep, qe, log_len);
	if (ret)
		ctrl_err(ep, "tcp_send_data failed with %d", errno);

	return ret;
}

int handle_request(struct endpoint *ep, struct nvme_command *cmd)
{
	struct ep_qe *qe;
	u32 len;
	u16 ccid;
	int ret;

	len = le32toh(cmd->common.dptr.sgl.length);
	/* ccid is considered opaque; no endian conversion */
	ccid = cmd->common.command_id;
	qe = tcp_acquire_tag(ep, ep->recv_pdu, ccid, 0, len);
	if (!qe) {
		struct nvme_completion resp = {
			.status = NVME_SC_NS_NOT_READY,
			.command_id = ccid,
		};

		ctrl_err(ep, "ccid %#x queue busy", ccid);
		return tcp_send_rsp(ep, &resp);
	}
	memset(&qe->resp, 0, sizeof(qe->resp));
	if (cmd->common.opcode == nvme_fabrics_command) {
		switch (cmd->fabrics.fctype) {
		case nvme_fabrics_type_property_set:
			ret = handle_property_set(ep, qe, cmd);
			break;
		case nvme_fabrics_type_property_get:
			ret = handle_property_get(ep, qe, cmd);
			break;
		case nvme_fabrics_type_connect:
			ret = handle_connect(ep, qe, cmd);
			break;
		default:
			ctrl_err(ep, "unknown fctype %d",
				 cmd->fabrics.fctype);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (ep->qid != 0) {
		ctrl_err(ep, "unknown nvme I/O opcode %d",
			 cmd->common.opcode);
		ret = NVME_SC_INVALID_OPCODE;
	} else if (cmd->common.opcode == nvme_admin_identify) {
		ret = handle_identify(ep, qe, cmd);
		if (!ret)
			return 0;
	} else if (cmd->common.opcode == nvme_admin_keep_alive) {
#ifdef DEBUG_COMMANDS
		print_debug("nvme_keep_alive ctrl %d qid %d",
			    ep->ctrl->cntlid, ep->qid);
#endif
		ret = 0;
	} else if (cmd->common.opcode == nvme_admin_get_log_page) {
		ret = handle_get_log_page(ep, qe, cmd);
		if (!ret)
			return 0;
	} else if (cmd->common.opcode == nvme_admin_set_features) {
		ret = handle_set_features(ep, qe, cmd);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
	} else {
		ctrl_err(ep, "unknown nvme admin opcode %d",
			 cmd->common.opcode);
		ret = NVME_SC_INVALID_OPCODE;
	}

	if (ret < 0) {
		ctrl_err(ep, "handle_request error %d", ret);
		return ret;
	}

	return send_response(ep, qe, ret);
}
