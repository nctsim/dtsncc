#include <flags.h>
#include <ip.h>
#include <stat.h>
#include "dtsncc-sink.h"

static class DTSNCCSinkClass : public TclClass {
public:
	DTSNCCSinkClass() : TclClass("Agent/DTSNCCSink") {}
	TclObject* create(int, const char*const*) {
		return (new DTSNCCSink(new DTSNCCFeedback));
	}
} class_dtsncc_sink;


DTSNCCFeedback::DTSNCCFeedback() : next_(0), maxseen_(0), wndmask_(MWM),
	ts_to_echo_(0), last_ack_sent_(0)
{
	seen_ = new int[MWS];
	memset(seen_, 0, (sizeof(int) * (MWS)));
}

DTSNCCSink::DTSNCCSink(DTSNCCFeedback* feedback) : Agent(PT_DTSNCC), feedback_(feedback), save_(NULL),
	lastreset_(0.0), first_(0), snd_wnd_(0), complete_(0), e2e_delay_min_(0), e2e_delay_max_(0),
	first_pkt_rcvd_(0), ack_sent_(0), pkt_missed_(0), sink_timer_(this), timer_active_(0),
 	ndatapack_(0), num_eot_(0)
{
	//bytes_ = 0;
	//bind("bytes_", &bytes_);
	bind("sink_timeout_", &sink_timeout_);
	recvseqno_ = new int[4000];
	memset(recvseqno_, 0, (sizeof(int) * (4000)));
	bind("maxseqno_", &maxseqno_);
	bind("snum_", &snum_);
}


void DTSNCCFeedback::reset()
{
	next_ = 0;
	maxseen_ = 0;
	memset(seen_, 0, (sizeof(int) * (wndmask_ + 1)));
}

void DTSNCCFeedback::resize_buffers(int sz) {
	int* new_seen = new int[sz];
	int new_wndmask = sz - 1;

	if(!new_seen){
		fprintf(stderr, "Unable to allocate buffer seen_[%i]\n", sz);
		exit(1);
	}

	memset(new_seen, 0, (sizeof(int) * (sz)));

	for(int i = next_; i <= maxseen_+1; i++){
		new_seen[i & new_wndmask] = seen_[i&wndmask_];
	}

	delete[] seen_;
	seen_ = new_seen;
	wndmask_ = new_wndmask;
	return;
}

void DTSNCCFeedback::update_ts(int seqno, double ts, int rfc1323)
{
	// update timestamp if segment advances with ACK.
	// Code changed by Andrei Gurtov.
	if (rfc1323 && seqno == last_ack_sent_ + 1)
		ts_to_echo_ = ts;
	else if (ts >= ts_to_echo_ && seqno <= last_ack_sent_ + 1)
         //rfc1323-bis, update timestamps from duplicate segments
    	ts_to_echo_ = ts;
}

int DTSNCCFeedback::update(int seq, int numBytes)
{

	bool just_marked_as_seen = FALSE;
	is_dup_ = FALSE;

	if (numBytes <= 0)
		printf("Error, received TCP packet size <= 0\n");
	int numToDeliver = 0;
	while(seq + 1 - next_ >= wndmask_) {
		// next_ is next packet expected; wndmask_ is the maximum
		// window size minus 1; if somehow the seqno of the
		// packet is greater than the one we're expecting+wndmask_,
		// then resize the buffer.
		resize_buffers((wndmask_+1)*2);
	}

	if (seq > maxseen_) {
		// the packet is the highest one we've seen so far
		int i;
		for (i = maxseen_ + 1; i < seq; ++i)
			seen_[i & wndmask_] = 0;
		// we record the packets between the old maximum and
		// the new max as being "unseen" i.e. 0 bytes of each
		// packet have been received
		maxseen_ = seq;
		seen_[maxseen_ & wndmask_] = numBytes;
		// store how many bytes have been seen for this packet
		seen_[(maxseen_ + 1) & wndmask_] = 0;
		// clear the array entry for the packet immediately
		// after this one
		just_marked_as_seen = TRUE;
		// necessary so this packet isn't confused as being a duplicate
	}

	int next = next_;
	if (seq < next) {
		// Duplicate packet case 1: the packet is to the left edge of
		// the receive window; therefore we must have seen it
		// before
#ifdef DEBUGDSACK
		printf("%f\t Received duplicate packet %d\n",Scheduler::instance().clock(),seq);
#endif
		is_dup_ = TRUE;
	}

	if (seq >= next && seq <= maxseen_) {
		// next is the left edge of the recv window; maxseen_
		// is the right edge; execute this block if there are
		// missing packets in the recv window AND if current
		// packet falls within those gaps

		if (seen_[seq & wndmask_] && !just_marked_as_seen) {
		// Duplicate case 2: the segment has already been
		// recorded as being received (AND not because we just
		// marked it as such)
			is_dup_ = TRUE;
#ifdef DEBUGDSACK
			printf("%f\t Received duplicate packet %d\n",Scheduler::instance().clock(),seq);
#endif
		}
		seen_[seq & wndmask_] = numBytes;
		// record the packet as being seen
		while (seen_[next & wndmask_]) {
			// this loop first gets executed if seq==next;
			// i.e., this is the next packet in order that
			// we've been waiting for.  the loop sets how
			// many bytes we can now deliver to the
			// application, due to this packet arriving
			// (and the prior arrival of any segments
			// immediately to the right)

			numToDeliver += seen_[next & wndmask_];
			++next;
		}
		next_ = next;
		// store the new left edge of the window
	}
	return numToDeliver;
}

int DTSNCCSink::command(int argc, const char*const* argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "reset") == 0) {
			reset();
			return (TCL_OK);
		}
		if (strcmp(argv[1], "resize_buffers") == 0) {
			// no need for this as seen buffer set dynamically
			fprintf(stderr,"DEPRECIATED: resize_buffers\n");
			return (TCL_OK);
		}
	}

	if (strcmp(argv[1], "set_trace_filename") == 0) {
		strcpy(tbuf, argv[2]);
		tFile = fopen(tbuf, "w");
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_maxseqno") == 0) {
		maxseqno_ = atoi(argv[2]);
		return (TCL_OK);
	}

	return (Agent::command(argc, argv));
}

void DTSNCCSink::reset()
{
	feedback_->reset();
	save_ = NULL;
	lastreset_ = NOW; /* W.N. - for detecting */
				/* packets from previous incarnations */
}

void DTSNCCSink::send_feedback()
{
	Packet* pkt = allocpkt();
	hdr_ip* ih = HDR_IP(pkt);
	hdr_dtsncc* th = HDR_DTSNCC(pkt);

	th->seqno() = feedback_->Maxseen();	// cumulative sequence number
	th->ts() = NOW;						// timestamp
	th->snum() = snum_;
	th->saddr() = addr();
 	th->daddr() = source_addr_;
 	th->data() = 0;
	th->cum_ack() = feedback_->Maxseen();

 	char NACK_list[100] = "\0";
 	char buffer[10];

 	int NACK_list_[64];
 	memset(NACK_list_, 0, (sizeof(int) * (64)));

 	int next;
 	int i, maxseq;
 	int j = 0;
 	int numholes = 0;

 	th->ts_echo() = th->ts();

 	//if ( (maxseqno_ - feedback_->Maxseen()) < 2)
 	//	maxseq = maxseqno_;
 	//else
 	//	maxseq = feedback_->Maxseen();

	//maxseq = feedback_->next_ + window_ -1;
	//maxseq = feedback_->last_ack_sent_ + window_ -1;
	//feedback_->last_ack_sent_ = th->seqno();
	//if (maxseq > maxseqno_) maxseq = maxseqno_;

 	for (i = feedback_->last_ack_sent_; i <= feedback_->Maxseen(); i++) {
 		if (!recvseqno_[i]) {
 			++numholes;
 			NACK_list_[j] = i;
 			++j;
 			sprintf(buffer, " %d ", i);
 			strcat(NACK_list, buffer);
 		}
 	}

 	//printf("snum: %d numholes: %d\n", snum_, numholes);

	memcpy(th->NACK_list_, NACK_list_, numholes*sizeof(int));
	th->num_holes() = numholes;

	if (numholes) {
		th->nack() = 1;
		th->ack() = 0;
		Stat::put("pkt_nack_sent", snum_, 1);
		}
	else {
		th->nack() = 0;
		th->ack() = 1;
		Stat::put("pkt_ack_sent", snum_, 1);
		}

	// copy NACK_list to feedback packet
	if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tHoles=%d [%s] cumACK = %d ack=%d nack=%d\n", NOW, th->snum(), th->seqno(), th->num_holes(), NACK_list, th->seqno(), th->ack(), th->nack() );

	if (timer_active_ && ndatapack_ == maxseqno_+1) {
		if (tFile!=NULL) fprintf(tFile, "%f Transmission complete pkts:%d\n", NOW, ndatapack_);
		complete_ = 1;

		// send EOT
		//th->nack() = 0;
		//th->ack() = 1;
	 	th->eot() = 1;
		}

	send(pkt, 0);
	//else
	//	sink_timer_.resched(sink_timeout_);
}

void DTSNCCSink::recv(Packet* pkt, Handler*)
{
	int numToDeliver;
	int numBytes = hdr_cmn::access(pkt)->size();
	// number of bytes in the packet just received

	hdr_dtsncc *th = HDR_DTSNCC(pkt);

	source_addr_ = th->saddr();
	// source address

	/* W.N. Check if packet is from previous incarnation */
	//if (th->ts() < lastreset_) {
		// Remove packet and do nothing
		//Packet::free(pkt);
	//	return;
	//}
	//feedback_->update_ts(th->seqno(),th->ts(),ts_echo_rfc1323_);
	// update the timestamp to echo

	if (!timer_active_) {
		timer_active_ = 1;
		//sink_timer_.sched(sink_timeout_);
		if (tFile!=NULL)
			fprintf(tFile,"%f \tTIMER activated pkts:%d maxseqno:%d\n", NOW, ndatapack_, maxseqno_);
		}

	if (th->data() && th->snum()==snum_) {

		//if (th->seqno() > feedback_->Maxseen()) feedback_->maxseen_ = th->seqno();
		// update maxseen_

		Stat::put("pkt_recv", snum_, 1);
		if ( !recvseqno_[th->seqno()] ) {
			// unique seqno

			recvseqno_[th->seqno()] = 1;
			// update receive map

			numToDeliver = feedback_->update(th->seqno(), numBytes);
			++ndatapack_;
			window_ = th->window();

			//printf("Delivering %d bytes\n", numToDeliver);
			//fprintf(tFile, "%f \t%d \t%d \t%d DATA received cached:%d rtx:%d\n", NOW, th->snum(), th->seqno(), numBytes, th->cached(), th->rtx() );

			if (tFile!=NULL) {
				if (th->cached()) fprintf(tFile, "%f \t%d \t%d \t%d CACHED_DATA src: %d \n", NOW, th->snum(), th->seqno(), numBytes, th->rtx_src() );
				else if (th->rtx()) fprintf(tFile, "%f \t%d \t%d \t%d RETX_DATA src: %d \n", NOW, th->snum(), th->seqno(), numBytes, th->rtx_src() );
				else fprintf(tFile, "%f \t%d \t%d \t%d \twin=%d DATA\n", NOW, th->snum(), th->seqno(), numBytes, th->window() );
				}

			if (th->cached()) Stat::put("pkt_recv_cached", snum_, 1);
				else if (th->rtx()) Stat::put("pkt_recv_rtx", snum_, 1);
				else Stat::put("pkt_recv_e2e", snum_, 1);

			}

		else {
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \t%d DUP_DATA src: %d \n", NOW, th->snum(), th->seqno(), numBytes, th->rtx_src() );
			// duplicate seqno
			Stat::put("pkt_recv_dup", snum_, 1);
			}
		}

	if (th->ear()) send_feedback();

	//if (th->ear() && th->snum()==snum_) {
	//	send_feedback();
	//	}

	//numToDeliver = feedback_->update(th->seqno(), numBytes);
	Packet::free(pkt);
	// remove it from the system
}


void DTSNCCSink::sink_timeout()
{
	// send NACK and reset sink_timer_
	//printf("sink_timer_ fired\n");
	if (tFile!=NULL)
		fprintf(tFile,"%f \tTIMER fired pkts:%d\n", NOW, ndatapack_);
	if (!complete_)  {
		send_feedback();
		sink_timer_.resched(sink_timeout_);
		}
	else sink_timer_.cancel();
}

void DTSNCCWatchdogTimer::expire(Event*)
{
	a_->sink_timeout();
}

