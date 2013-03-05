#ifndef ns_dtsncc_h
#define ns_dtsncc_h

#include <packet.h>
#include <agent.h>
#include "aodv/aodv.h"

#define TCP_MAXSEQ 1073741824  
#define NOW	Scheduler::instance().clock()
#define wnd_ 64

//ETX probe packets
/*
struct hdr_etx_ {
	int pkt_recv_;

  	static int offset_;	      	// offset for this header
	inline static int& offset() { return offset_; }
	inline static hdr_etx* access(const Packet* p) {
		return (hdr_etx*) p->access(offset_);
};
*/

//DTSNCC Header Structure
struct hdr_dtsncc {
	nsaddr_t srcaddr_;
	nsaddr_t destaddr_;
	int AMID_;
	int snum_;
	int seqno_;					// DTSNCC sequence number
	int nextseqno_;				// next sequence number expected
	int maxseqno_;				// highest sequence number in the window
	int earseqno_;
	int NACKbitmap_[64];		// NACK bitmap
	int EARbitmap_[64];			// EAR bitmap
	int RNACKbitmap_[64];		// Repair bitmap
	int numholes_;
	int NACK_list_[64];
	struct dtsn_flags_{			// DTSNCC flags:
		int rtx;				// retransmitted packet
		int ack;				// ACK packet
		int nack;				// NACK packet
		int ear;				// EAR packet
		int data;				// data packet
		int rst;				// reset packet (initial)
		int cached;				// cached packet
		int disc;				// disconnect packet
		int cc;             	// congestion control
		int rnack;				// single packet repair
		int crnack;				// cumulative packet repair
		int eot;
		int rep_data;			// repair data packet
		} flags_;
	int cum_ack_;
	int rtx_src_;
	int hops_to_dst_;			// hops to destination
	int hops_to_src_;			// hops to source
	int nack_hops_;				// hops to first cached packet after NACK is sent		
	double ts_;					// timestamp
	double ts_echo_;			// the echoed timestamp 
	int last_rtt_;
	double snd_time_;
	int hlen_;					// header length
	int size_;
	int earindex_;
	int src_cached_;
	double avg_cache_size_;
	int window_size_;
	int num_mac_attempts_;
	double velocity_;			// velocity
	double deadline_;			// realtime deadline
	int highprio_;				// high priority
	int lasthop_;
	int nexthop_;
	int etx_;
	int myaddr_;
	int endseqno_;

  	static int offset_;	      	// offset for this header
	inline static int& offset() { return offset_; }
	inline static hdr_dtsncc* access(const Packet* p) {
		return (hdr_dtsncc*) p->access(offset_);
	};

	int& size() {return size_;}
	int& hlen() { return (hlen_); }
	double& ts() { return (ts_); }
	double& ts_echo() { return (ts_echo_); }
	int& last_rtt() { return (last_rtt_); }
	
/* per-field member functions */	
	int& seqno() { return (seqno_); }
	int& snum() { return (snum_); }
	int& saddr() { return (srcaddr_); }
	int& daddr() { return (destaddr_); }
	int& myaddr() { return (myaddr_); };
	struct dtsn_flags_& flags() { return (flags_); }
	int& data() { return (flags_.data); }
	int& ear() { return (flags_.ear); }
	int& ack() { return (flags_.ack); }
	int& nack() { return (flags_.nack); }
	int& rtx() { return (flags_.rtx); }
	int& rst() { return (flags_.rst); }
	int& disc() { return (flags_.disc); }
	int& rnack() { return (flags_.rnack); }
	int& crnack() { return (flags_.crnack); }
	int& cached() { return (flags_.cached); }
	int& eot() { return (flags_.eot); }
	int& rep_data() { return (flags_.rep_data); }
	int& window() { return (window_size_); }
	int& maxseqno() { return (maxseqno_); }
	int& num_mac_attempts() { return (num_mac_attempts_); }
	double& velocity() { return (velocity_); }
	double& deadline() { return (deadline_); }
	int& highprio() { return (highprio_); }
	int& lasthop() { return (lasthop_); }
	int& nexthop() { return (nexthop_); }
	int& etx() { return (etx_); }
	int& num_holes() { return (numholes_); }
	int& earseqno() { return (earseqno_); }
	int& cum_ack() { return (cum_ack_); }
	int& rtx_src() { return (rtx_src_); }
	int& endseqno() { return (endseqno_); }
};

class DTSNCCAgent;

class DTSNCCEarTimer : public TimerHandler {
public:
	DTSNCCEarTimer(DTSNCCAgent *a) : TimerHandler() { a_ = a; }
	virtual void expire(Event *e);
protected:
	DTSNCCAgent *a_;
};

class DTSNCCSendTimer : public TimerHandler {
public:
	DTSNCCSendTimer(DTSNCCAgent *a) : TimerHandler() { a_ = a; }
	virtual void expire(Event *e);
protected:
	DTSNCCAgent *a_;
};

class DTSNCCAgent : public Agent {
public:
	DTSNCCAgent();
	virtual ~DTSNCCAgent() {}
  	virtual void recv(Packet*, Handler*);
	virtual void timeout();
	virtual void set_dtsncc_timer();
	virtual void reset_dtsncc_timer(int mild, int backoff);
	virtual int command(int argc, const char*const* argv);
	virtual void sendmsg(int nbytes, const char *flags = 0);
	virtual void send_much(int force, int reason, int maxburst);
	virtual void output(int seqno);
	virtual void output_ear(int seqno);
	virtual void output_ear_standalone(int seqno);
	virtual int window();
	virtual void rtt_init();
	virtual double rtt_timeout();
	virtual void rtt_backoff();
	virtual void rtt_update(double tao);
	virtual void getAODVAgent();

protected:
	DTSNCCEarTimer dtsncc_ear_timer_;
	DTSNCCSendTimer dtsncc_send_timer_;
	int seqno_;
	char tbuf[100];
	FILE *tFile;
	double eartimeout_;
	int maxseqno_;
	int t_seqno_;
	int highest_ack_;
	int prev_highest_ack_;
	int curseq_;
	int ndatapack_;
	int ndatabytes_;
	double *tss;            // To store sent timestamps, with bugfix_ts_
	int tss_size_;          // Current capacity of tss
	int snum_;
	int earseqno_;
	int maxseq_;
	double CI_;
	double ts_peer_;
	double tcp_tick_;
	double deadline_;
	int cwnd_;
	int twnd_;				// transmission window
	int last_ack_;
	int pendingACK_;
	int rtt_active_;
	int rtt_seq_;
	double rtt_ts_;
	int t_rtt_;
	int t_srtt_;
	int t_rttvar_;
	int t_backoff_;
	double ts_echo_;
	double last_reset_;
	int pkt_count_;
	double srtt_init_;
	int rttvar_init_;
	double rtt_var_;
	double rtxcur_init_;
	double lastreset_;
	int *sentseqno_;
	int highest_seqno_;

	int nrexmitpack_;
	int nrexmitbytes_;
	int bufsize_;
	int ntokens_;
	double demand_rate_;
	double assigned_rate_;
	double interval_;
	int numholes_;

	double boot_time_;
	int T_SRTT_BITS;
	int T_RTTVAR_BITS;
	double t_rtxcur_;
	int rttvar_exp_;
	int rfc2988_;

	double maxrto_;
	double minrto_;
	int use_rtt_;
	int complete_;
	AODV *aodvagent_;
	int numhops_;
	int maxwndseqno_;
	int startwin_;
	double ear_timeout_;
	double ear_interval_;
	int ACK_pending_;
	int rtt_ack_;
	int repair_enabled_;
	int conf_ear_interval_;
};

#endif
