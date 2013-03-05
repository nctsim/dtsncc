/*
 * DTSNCC Implementation
 * 20 July 2012
 */

#include <stat.h>
#include <ip.h>
#include "dtsncc.h"
#include "random.h"

int hdr_dtsncc::offset_;

static class DTSNCCHeaderClass : public PacketHeaderClass {
public:
	DTSNCCHeaderClass() : PacketHeaderClass("PacketHeader/DTSNCC", sizeof(hdr_dtsncc)) {
		bind_offset(&hdr_dtsncc::offset_);
	}
} class_dtsncchdr;

static class DTSNCCClass : public TclClass {
public:
	DTSNCCClass() : TclClass("Agent/DTSNCC") {}
	TclObject* create(int , const char*const*) {
		return (new DTSNCCAgent());
	}
} class_dtsncc;

DTSNCCAgent::DTSNCCAgent() : Agent(PT_DTSNCC),
		t_seqno_(0), t_rtt_(0), t_srtt_(0), t_rttvar_(0),
		ts_peer_(0), ts_echo_(0), tcp_tick_(0.1),
		tss(NULL), tss_size_(100), rtt_active_(0), rtt_seq_(-1), rtt_ts_(0.0),
		curseq_(0), highest_ack_(-1), maxseq_(-1), lastreset_(0.0),
		pendingACK_(0), pkt_count_(0), dtsncc_send_timer_(this), dtsncc_ear_timer_(this),
		deadline_(2), ndatabytes_(0), ndatapack_(0), srtt_init_(0),
		rttvar_init_(12), rtxcur_init_(1), CI_(0), earseqno_(0), last_ack_(-1),
		numholes_(0), complete_(0), numhops_(255), cwnd_(2),
		maxwndseqno_(0), startwin_(0), ear_timeout_(0.2), ACK_pending_(0), repair_enabled_(0)
	{
		bind("packetSize_", &size_);
		bind("snum_", &snum_);
		sentseqno_ = new int[4000];
		memset(sentseqno_, 0, (sizeof(int) * (4000)));
		bind("maxseqno_", &maxseqno_);
		bind("winsize_", &cwnd_);
		bind("T_SRTT_BITS", &T_SRTT_BITS);
		bind("T_RTTVAR_BITS", &T_RTTVAR_BITS);
		bind("tcp_tick_", &tcp_tick_);
		boot_time_ = Random::uniform(tcp_tick_);
		bind("ear_interval_", &ear_interval_);
		bind("conf_ear_interval_", &conf_ear_interval_);
		bind("minrto_", &minrto_);
		bind("maxrto_", &maxrto_);
		bind("rfc2988_", &rfc2988_);
		rtt_init();
	}

// BDP
static int BDP[20] = {0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4 , 4 , 4 };

int DTSNCCAgent::window()
{
	return (cwnd_ < wnd_ ? (int)cwnd_ : (int)wnd_);
}

void DTSNCCAgent::recv(Packet *pkt, Handler*)
{
	hdr_dtsncc *th = HDR_DTSNCC(pkt);

 	char NACK_list[100] = "\0";
 	char buffer[10];

	numholes_ = 0;

	if ((th->ack() || th->nack()) &&  th->snum()==snum_) {

		if (th->seqno() > last_ack_) {
			last_ack_ = th->seqno();
			prev_highest_ack_ = highest_ack_;
			highest_ack_ = last_ack_;
			}

		//if (rtt_active_ && th->seqno() >= rtt_seq_) {
		if (rtt_active_ ) {
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \tRTTSEQ update tao: %f\n", NOW, rtt_seq_, NOW - th->ts_echo() );
			rtt_active_ = 0;
			rtt_update(NOW - th->ts_echo());
			}

		// if there are missing packets, retransmit them
		if (th->nack() && th->snum() == snum_) {
			Stat::put("pkt_nack_recv", snum_, 1);
			ACK_pending_ = 0;

			int i;
			for (i = 0; i < th->num_holes(); i++) {
 				sprintf(buffer, "%d-", th->NACK_list_[i]);
 				strcat(NACK_list, buffer);
				}
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tNACK holes = %d [%s] cumACK = %d\n", NOW, th->snum(), th->seqno(), th->num_holes(), NACK_list, th->cum_ack() );

			// retransmit lost packets
			numholes_ = th->num_holes();
			for (i = 0; i < th->num_holes(); i++) {
				//if (tFile!=NULL) fprintf(tFile, "%f \t%d \tSending lost pkts\n", NOW, th->snum() );
				output(th->NACK_list_[i]);
				}
			}

		// no missing packets
		else if (!th->nack() && th->snum() == snum_) {
			Stat::put("pkt_ack_recv", snum_, 1);
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tACK holes = %d [] cumACK = %d\n", NOW, th->snum(), th->seqno(), th->num_holes(),  th->cum_ack() );
			ACK_pending_ = 0;
			}


		if (th->eot() && th->snum() == snum_ && !complete_) {
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tEOT received\n", NOW, th->snum(), th->seqno() );
			dtsncc_send_timer_.force_cancel();
			complete_ = 1;

			printf("\nSESSION %d \n", snum_);
			Stat::put("pktno", snum_, curseq_);
			printf ("Bytes: %d Tput: %f \n", (int)ndatabytes_, ndatabytes_*8/(NOW-100));
			Stat::put("tput", snum_, (double)ndatabytes_*8/(NOW-100));
			Stat::put("goodput", snum_, (double)curseq_*8*500/(NOW-100));

			double tmp;
			tmp = (double)( Stat::get("ll_data_sent",snum_) + Stat::get("ll_nack_sent",snum_) + Stat::get("ll_ack_sent",snum_) + \
					Stat::get("ll_mack_sent",snum_)) / Stat::get("pktno", snum_);

			printf("Transfer time: %f Rate: %f Goodput: %f Cost: %f\n", NOW-100, (double)curseq_/(NOW-100), curseq_*8*500/(NOW-100), tmp);
			Stat::put("trans_time", snum_, NOW-100);
			Stat::put("trans_rate", snum_, (double)curseq_/(NOW-100));
			Stat::put("cwnd", snum_, cwnd_);
			Stat::put("numhops", snum_, numhops_);
			Stat::put("tx_cost", th->snum(), tmp);
			//getAODVAgent();
			}
		else if (!th->eot() && th->snum() == snum_) {
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \tSend much\n", NOW, snum_ );
			send_much(0,1,1000);
			}
		}

	if (th->rnack() &&  th->snum()==snum_) {
		if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tRNACK received\n", NOW, th->snum(), th->seqno() );
		repair_enabled_ = 1;
		if (th->seqno() >= highest_ack_) output(th->seqno());
		}
	Packet::free(pkt);
}

/*
void DTSNCCAgent::output_ear(int seqno)
{
	Packet* p = allocpkt();
	hdr_cmn *ch = HDR_CMN(p);
	hdr_dtsncc *th = HDR_DTSNCC(p);
	hdr_ip* iph = HDR_IP(p);

	ch->size() = 1;
	th->snum() = snum_;
	th->seqno() = seqno;
	th->ts() = NOW;

	// DTSN sessionID
	th->saddr() = iph->saddr();
  	th->daddr() = iph->daddr();

	// DTSN flags
	th->data() = 0;
	th->ear() = 1;
	if (tFile!=NULL)
		fprintf(tFile, "%f \t%d \t%d \t%d \tEAR\n", NOW, th->snum(), th->seqno(), ch->size());
	CI_ = CI_ + 1;
	if (tFile!=NULL)
		fprintf(tFile, "CI %f \t%d \t%f \n", NOW, th->snum(), CI_ );
	send(p,0);
}
*/

void DTSNCCAgent::output_ear_standalone(int seqno)
{
	int is_retransmit = (seqno <= maxseq_);

	Packet* p = allocpkt();
	hdr_cmn* ch = HDR_CMN(p);
	hdr_dtsncc* th = HDR_DTSNCC(p);
	hdr_ip* iph = HDR_IP(p);
	int force_set_timer = 0;

	ch->size() = size_;
	th->seqno() = seqno;
	th->ts() = NOW;
	th->saddr() = iph->saddr();
  	th->daddr() = iph->daddr();
  	th->snum() = snum_;
	th->ear() = 1;
	th->maxseqno() = maxseqno_;
	th->data() = 0;
	th->window() = window();
	th->endseqno() = curseq_;
	if (is_retransmit) th->rtx() = 1;

	send(p,0);

	if (tFile!=NULL) {
		if (!is_retransmit)
			fprintf(tFile, "%f \t%d \t%d \t%d EAR\n", NOW, th->snum(), th->seqno(), ch->size());
		else
			fprintf(tFile, "%f \t%d \t%d \t%d EAR Rtxd\n", NOW, th->snum(), th->seqno(), ch->size());
		}

	if (!dtsncc_send_timer_.status() == TIMER_PENDING || force_set_timer)
		set_dtsncc_timer();
}

void DTSNCCAgent::output_ear(int seqno)
{
	int is_retransmit = (seqno <= maxseq_);

	Packet* p = allocpkt();
	hdr_cmn* ch = HDR_CMN(p);
	hdr_dtsncc* th = HDR_DTSNCC(p);
	hdr_ip* iph = HDR_IP(p);
	int force_set_timer = 0;

	ch->size() = size_;
	th->seqno() = seqno;
	th->ts() = NOW;

	int databytes = HDR_CMN(p)->size();

	th->saddr() = iph->saddr();
  	th->daddr() = iph->daddr();
  	th->snum() = snum_;
	th->ear() = 1;
	th->maxseqno() = maxseqno_;
	th->data() = 1;
	th->window() = window();
	th->endseqno() = curseq_;
	if (is_retransmit) th->rtx() = 1;

	/* Store timestamp */
	int bugfix_ts_ = 1;
	if (bugfix_ts_ && tss==NULL) {
		tss = (double*) calloc(tss_size_, sizeof(double));
        if (tss==NULL) exit(1);
	}
    //dynamically grow the timestamp array if it's getting full
	if (bugfix_ts_ && window() > tss_size_* 0.9) {
		double *ntss;
        ntss = (double*) calloc(tss_size_*2, sizeof(double));
        printf("resizing timestamp table\n");
        if (ntss == NULL) exit(1);
        for (int i=0; i<tss_size_; i++)
        	ntss[(highest_ack_ + i) % (tss_size_ * 2)] =
            tss[(highest_ack_ + i) % tss_size_];
            free(tss);
            tss_size_ *= 2;
            tss = ntss;
        }

	if (tss!=NULL)
		tss[seqno % tss_size_] = th->ts();

	th->ts_echo() = ts_peer_;
	//th->reason() = reason;
	//printf ("Timestamp: %f last_rtt:%f\n", tss[seqno % tss_size_], th->last_rtt());

	/* Real-time support */
	th->ts() = NOW;
	if (highest_ack_ == maxseq_) force_set_timer = 1;

	++ndatapack_;
	ndatabytes_ += databytes;
	Stat::put("pkt_sent", snum_, 1);
	if (is_retransmit) Stat::put("pkt_sent_rtx", snum_, 1);

	if (sentseqno_[seqno] == 0) {
		sentseqno_[seqno] = 1;
		}

	//if (numhops_ == 255 || numhops_ == 0)
	//getAODVAgent();

	send(p,0);

	if (tFile!=NULL) {
		if (!is_retransmit)
			fprintf(tFile, "%f \t%d \t%d \t%d DATA_EAR\n", NOW, th->snum(), th->seqno(), ch->size());
		else
			fprintf(tFile, "%f \t%d \t%d \t%d DATA_EAR Rtxd\n", NOW, th->snum(), th->seqno(), ch->size());
		}

	if (seqno == curseq_ && seqno > maxseq_)
		idle();  // Tell application I have sent everything so far

	if (seqno > maxseq_) {
		//if (tFile!=NULL) fprintf(tFile, "%f \t%d \tMAXSEQ\n", NOW, maxseq_);
		maxseq_ = seqno;
		if (!rtt_active_) {
			rtt_active_ = 1;
			if (seqno > rtt_seq_) {
				rtt_seq_ = seqno;
				rtt_ts_ = NOW;
			}

		}
	} else {
    	++nrexmitpack_;
		nrexmitbytes_ += databytes;
	}

	if (!dtsncc_send_timer_.status() == TIMER_PENDING || force_set_timer)
		set_dtsncc_timer();
}

void DTSNCCAgent::output(int seqno)
{
	int is_retransmit = (seqno <= maxseq_);

	Packet* p = allocpkt();
	hdr_cmn* ch = HDR_CMN(p);
	hdr_dtsncc* th = HDR_DTSNCC(p);
	hdr_ip* iph = HDR_IP(p);
	int force_set_timer = 0;

	ch->size() = size_;
	th->seqno() = seqno;
	th->ts() = NOW;

	int databytes = HDR_CMN(p)->size();

	th->saddr() = iph->saddr();
  	th->daddr() = iph->daddr();
  	th->snum() = snum_;
	th->ear() = 0;
	th->maxseqno() = maxseqno_;
	th->data() = 1;
	th->window() = window();
	th->endseqno() = curseq_;
	if (is_retransmit) th->rtx() = 1;

	/* Store timestamp */
	int bugfix_ts_ = 1;
	if (bugfix_ts_ && tss==NULL) {
		tss = (double*) calloc(tss_size_, sizeof(double));
        if (tss==NULL) exit(1);
	}
    //dynamically grow the timestamp array if it's getting full
	if (bugfix_ts_ && window() > tss_size_* 0.9) {
		double *ntss;
        ntss = (double*) calloc(tss_size_*2, sizeof(double));
        printf("resizing timestamp table\n");
        if (ntss == NULL) exit(1);
        for (int i=0; i<tss_size_; i++)
        	ntss[(highest_ack_ + i) % (tss_size_ * 2)] =
            tss[(highest_ack_ + i) % tss_size_];
            free(tss);
            tss_size_ *= 2;
            tss = ntss;
        }

	if (tss!=NULL)
		tss[seqno % tss_size_] = th->ts();

	th->ts_echo() = ts_peer_;
	//th->reason() = reason;
	//printf ("Timestamp: %f last_rtt:%f\n", tss[seqno % tss_size_], th->last_rtt());

	/* Real-time support */
	th->ts() = NOW;
	if (highest_ack_ == maxseq_) force_set_timer = 1;

	++ndatapack_;
	ndatabytes_ += databytes;
	Stat::put("pkt_sent", snum_, 1);
	if (is_retransmit) Stat::put("pkt_sent_rtx", snum_, 1);

	if (sentseqno_[seqno] == 0) {
		sentseqno_[seqno] = 1;
		}

	//if (numhops_ == 255 || numhops_ == 0)
	//getAODVAgent();

	send(p,0);

	if (tFile!=NULL) {
		if (!is_retransmit)
			fprintf(tFile, "%f \t%d \t%d \t%d DATA\n", NOW, th->snum(), th->seqno(), ch->size());
		else
			fprintf(tFile, "%f \t%d \t%d \t%d DATA Rtxd\n", NOW, th->snum(), th->seqno(), ch->size());
		}

	if (seqno == curseq_ && seqno > maxseq_)
		idle();  // Tell application I have sent everything so far

	if (seqno > maxseq_) {
		//if (tFile!=NULL) fprintf(tFile, "%f \t%d \tMAXSEQ\n", NOW, maxseq_);
		maxseq_ = seqno;
		//if (!rtt_active_) {
		//	rtt_active_ = 1;
		//	if (seqno > rtt_seq_) {
		//		rtt_seq_ = seqno;
		//		rtt_ts_ = NOW;
		//	}
		//}
	} else {
    	++nrexmitpack_;
		nrexmitbytes_ += databytes;
	}

	//if (!dtsncc_send_timer_.status() == TIMER_PENDING || force_set_timer)
	//	set_dtsncc_timer();

}

void DTSNCCAgent::send_much(int force, int reason, int maxburst)
{
	int npackets = 0;

	int win = cwnd_;
	int seqno = t_seqno_;
	int sent_some = 0;

	while (t_seqno_ <= highest_ack_ + win - numholes_ && t_seqno_ < curseq_) {
		if (!sent_some) sent_some = 1;
		//if (t_seqno_ != highest_ack_) output(t_seqno_);
		if (t_seqno_ == highest_ack_ + win - numholes_ && reason) output_ear(t_seqno_);
		else output(t_seqno_);
		//printf("Sending packet nbytes: %d %d %d\n", size_, seqno, cwnd_);
		npackets++;
		t_seqno_++;
		seqno = t_seqno_;
		}

	if (!sent_some) {
		maxwndseqno_ = t_seqno_ - 1;
		if (win>1) output_ear_standalone(t_seqno_-1);
		}

	//if (t_seqno_ == curseq_ && !reason) output(curseq_ - 1);
	//else if (t_seqno_ == curseq_ && reason) output_ear(curseq_ - 1);
}

void DTSNCCAgent::sendmsg(int nbytes, const char* /*flags*/)
{

	if (nbytes == -1 && curseq_ <= TCP_MAXSEQ)
		curseq_ = TCP_MAXSEQ;
	else
		curseq_ += (nbytes/size_ + (nbytes%size_ ? 1 : 0));

	printf("snum: %d size: %d curseq: %d\n", snum_, size_, curseq_);
	//dtpa_send_timer_.sched(interval_);
	//if (tFile!=NULL) fprintf(tFile, "%f \t%d \tSend much\n", NOW, snum_ );
	send_much(0, 1, 1000);

}

int DTSNCCAgent::command(int argc, const char*const* argv)
{
 	Tcl& tcl = Tcl::instance();

	if (strcmp(argv[1], "attach") == 0) {
		int mode;
		const char* id = argv[2];
		channel_ = Tcl_GetChannel(tcl.interp(), (char*)id, &mode);
		if (channel_ == 0) {
			tcl.resultf("trace: can't attach %s for writing", id);
			return (TCL_ERROR);
		}
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_trace_filename") == 0) {
		strcpy(tbuf, argv[2]);
		tFile = fopen(tbuf, "w");
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_ear_interval") == 0) {
		ear_interval_ = atof(argv[2]);
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_maxseqno") == 0) {
		maxseqno_ = atoi(argv[2]);
		return (TCL_OK);
	}

	if (strcmp(argv[1], "closefile") == 0) {
		fclose(tFile);
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_repair") == 0) {
		repair_enabled_ = atoi(argv[2]);
		return (TCL_OK);
		}

	if (strcmp(argv[1], "conf_ear_interval") == 0) {
		conf_ear_interval_ = atoi(argv[2]);
		return (TCL_OK);
		}

	return (Agent::command(argc, argv));
}


void DTSNCCAgent::timeout()
{
	// EAR timeout, resend EAR
	if (tFile!=NULL) fprintf(tFile, "%f \t%d \tTIMER_fired\n", NOW, snum_);
	//if (highest_ack_ != -1 && t_seqno_ < curseq_) output(highest_ack_+1);
	//else if (highest_ack_ == -1) output(0);
	//else if (t_seqno_ == curseq_) output(curseq_ - 1);
	reset_dtsncc_timer(0,1);
	//send_much(0, 1, 1000);
	if (!ACK_pending_) ACK_pending_ = 1;
	if (ACK_pending_) output_ear(maxseq_);
	else send_much(0, 0, 1000);
	//if (t_seqno_ - 1 < 0) output_ear(t_seqno_ - 1);
	//else output_ear(0);
}

void DTSNCCEarTimer::expire(Event*)
{
	a_->timeout();
}

void DTSNCCSendTimer::expire(Event*)
{
	a_->timeout();
}

void DTSNCCAgent::set_dtsncc_timer()
{
	double timeout;

	if (!complete_) {
		//if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%f \tTimer set\n", NOW, snum_, rtt_timeout());
		//if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tTIMER_set %f\n", NOW, snum_, rtt_seq_, rtt_timeout());
		//if (tFile!=NULL) fprintf(tFile, "%f \t%d \tTimer set %f \n", NOW, snum_, ear_interval_);
		//if (!repair_enabled_) {
		if (!conf_ear_interval_) {
			dtsncc_send_timer_.resched(rtt_timeout());
			timeout = rtt_timeout();
			}
		else {
			dtsncc_send_timer_.resched(ear_interval_);
			timeout = ear_interval_;
			}
		if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tTIMER_set %f\n", NOW, snum_, rtt_seq_, timeout);
		}
}

void DTSNCCAgent::reset_dtsncc_timer(int mild, int backoff)
{
	//if (backoff)
		//rtt_backoff();
	set_dtsncc_timer();
	//if (!mild)
		//t_seqno_ = highest_ack_ + 1;
	rtt_active_ = 0;
}


void DTSNCCAgent::rtt_init()
{
	t_rtt_ = 0;
	t_srtt_ = int(srtt_init_ / tcp_tick_) << T_SRTT_BITS;
	t_rttvar_ = int(rttvar_init_ / tcp_tick_) << T_RTTVAR_BITS;
	t_rtxcur_ = rtxcur_init_;
	t_backoff_ = 1;
}

double DTSNCCAgent::rtt_timeout()
{
	double timeout;
	if (rfc2988_) {
	// Correction from Tom Kelly to be RFC2988-compliant, by
	// clamping minrto_ before applying t_backoff_.
		if (t_rtxcur_ < minrto_ && !use_rtt_)
			timeout = minrto_ * t_backoff_;
		else
			timeout = t_rtxcur_ * t_backoff_;
	} else {
		// only of interest for backwards compatibility
		timeout = t_rtxcur_ * t_backoff_;
		if (timeout < minrto_)
			timeout = minrto_;
	}

	if (timeout > maxrto_)
		timeout = maxrto_;

        if (timeout < 2.0 * tcp_tick_) {
		if (timeout < 0) {
			fprintf(stderr, "TcpAgent: negative RTO!  (%f)\n",
				timeout);
			exit(1);
		} else if (use_rtt_ && timeout < tcp_tick_)
			timeout = tcp_tick_;
		else
			timeout = 2.0 * tcp_tick_;
	}
	use_rtt_ = 0;
	return (timeout);
}

void DTSNCCAgent::rtt_update(double tao)
{
	double now = NOW;

	double sendtime = now - tao;
	sendtime += boot_time_;
	double tickoff = fmod(sendtime, tcp_tick_);
	t_rtt_ = int((tao + tickoff) / tcp_tick_);

	if (t_rtt_ < 1)
		t_rtt_ = 1;
	//
	// t_srtt_ has 3 bits to the right of the binary point
	// t_rttvar_ has 2
        // Thus "t_srtt_ >> T_SRTT_BITS" is the actual srtt,
  	//   and "t_srtt_" is 8*srtt.
	// Similarly, "t_rttvar_ >> T_RTTVAR_BITS" is the actual rttvar,
	//   and "t_rttvar_" is 4*rttvar.
	//
    if (t_srtt_ != 0) {
		register short delta;
		delta = t_rtt_ - (t_srtt_ >> T_SRTT_BITS);	// d = (m - a0)
		if ((t_srtt_ += delta) <= 0)	// a1 = 7/8 a0 + 1/8 m
			t_srtt_ = 1;
		if (delta < 0)
			delta = -delta;
		delta -= (t_rttvar_ >> T_RTTVAR_BITS);
		if ((t_rttvar_ += delta) <= 0)	// var1 = 3/4 var0 + 1/4 |d|
			t_rttvar_ = 1;
	} else {
		t_srtt_ = t_rtt_ << T_SRTT_BITS;		// srtt = rtt
		t_rttvar_ = t_rtt_ << (T_RTTVAR_BITS-1);	// rttvar = rtt / 2
	}
	//
	// Current retransmit value is
	//    (unscaled) smoothed round trip estimate
	//    plus 2^rttvar_exp_ times (unscaled) rttvar.
	//
	t_rtxcur_ = (((t_rttvar_ << (rttvar_exp_ + (T_SRTT_BITS - T_RTTVAR_BITS))) +
		t_srtt_)  >> T_SRTT_BITS ) * tcp_tick_;

	//printf("snum: %d RTT value: %f\n", snum_, t_rtxcur_);
	//if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%f \tRTT\n", NOW, snum_, t_rtxcur_);
	return;
}

void DTSNCCAgent::rtt_backoff()
{
	if (t_backoff_ < 64)
		t_backoff_ <<= 1;

	if (t_backoff_ > 8) {
		/*
		 * If backed off this far, clobber the srtt
		 * value, storing it in the mean deviation
		 * instead.
		 */
		t_rttvar_ += (t_srtt_ >> T_SRTT_BITS);
		t_srtt_ = 0;
	}
}

void DTSNCCAgent::getAODVAgent()
{
	char command[256];
	int i = here_.addr_;

	sprintf(command, "foreach aodvagent [Agent/AODV info instances]\ {\nif { [$aodvagent id] == %d } {\nset i $aodvagent}}\nset t $i\n", i);

	//printf("%s\n", command);
	Tcl& tcl = Tcl::instance();
	tcl.eval(command);
	const char* ref = tcl.result();

	aodvagent_ = (AODV*)tcl.lookup(ref);
	numhops_ = aodvagent_->get_num_hops(here_.addr_, dst_.addr_);
	//printf("snum: %d id: %d dst: %d hops: %d\n", snum_, i, dst_.addr_, numhops_);
	if (numhops_ != 255 && numhops_ != 0 && numhops_ < 30)
		cwnd_ = BDP[numhops_] - 3;
	if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tCWND\n", NOW, snum_, cwnd_);
}
