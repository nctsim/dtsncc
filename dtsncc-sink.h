#ifndef ns_dtpasink_h
#define ns_dtpasink_h

#include <packet.h>
#include <agent.h>
#include "dtsncc.h"

#define MWS 64
#define MWM (MWS-1)

class DTSNCCSink;
class DTSNCCFeedback {
friend class DTSNCCSink;
public:
	DTSNCCFeedback();
	virtual ~DTSNCCFeedback() { delete[] seen_;}
	void reset();
	int update(int seqno, int numBytes);
	void update_ts(int seqno, double ts, int rfc1323 = 0);
	inline int Seqno() const { return (next_ - 1); }
	double ts_to_echo() { return ts_to_echo_;}
	inline int Maxseen() const { return (maxseen_); }
	void resize_buffers(int sz);
	int *get_bitmap(int first, int snd_wnd);

protected:
	int maxseen_;
	int wndmask_;
	int *seen_;
	int ecn_unacked_;
	double ts_to_echo_;

public:
	int is_dup_;
	int last_ack_sent_;
	int next_;
};

class DTSNCCSink;

class DTSNCCWatchdogTimer : public TimerHandler {
public:
	DTSNCCWatchdogTimer(DTSNCCSink *a) : TimerHandler() { a_ = a; }
protected:
	virtual void expire(Event *e);
	DTSNCCSink *a_;
};


class DTSNCCSink : public Agent {
public:
	DTSNCCSink(DTSNCCFeedback*);
	void recv(Packet* pkt, Handler*);
	void reset();
	int command(int argc, const char*const* argv);
	inline int first() const { return (first_); }
	inline int last() const { return (last_); }
	char *get_bitmap_string(int *NACKbitmap);
	int get_numlost(int *NACKbitmap);
	virtual void sink_timeout();

protected:
	DTSNCCFeedback* feedback_;
	void send_feedback();

	/* Timer */
	DTSNCCWatchdogTimer sink_timer_;
	int timer_active_;
	double sink_timeout_;

	int ts_echo_bugfix_;
	int ts_echo_rfc1323_;
	Packet* save_;		/* place to stash saved packet while delaying */
	double lastreset_; 	/* W.N. used for detecting packets  */
	int bytes_;
	char tbuf[100];
	FILE *tFile;
	int first_;
	int last_;
	int snd_wnd_;
	int first_pkt_rcvd_;
	int maxseqno_;
	int ndatapack_;
	int revnexthop_[100];
	double e2e_delay_;
	double e2e_delay_min_;
	double e2e_delay_max_;
	int *recvseqno_;
	int ack_sent_;
	int pkt_missed_;
	int source_addr_;
	int snum_;
	int num_eot_;
	int complete_;
	int window_;
};

#endif
