#ifndef ns_dtsncc_cache_h
#define ns_dtsncc_cache_h

#include <agent.h>
#include <packet.h>
#include <math.h>
#include "dtsncc.h"
#include <ndtsn/ndtsn-cache.h>

class DTSNCCCacheAgent;

class DTSNCCForwardTimer : public TimerHandler {
public:
	DTSNCCForwardTimer(DTSNCCCacheAgent *a) : TimerHandler() { a_ = a; }
protected:
	virtual void expire(Event *e);
	DTSNCCCacheAgent *a_;
};

class DTSNCCRepairTimer : public TimerHandler {
public:
	DTSNCCRepairTimer(DTSNCCCacheAgent *a) : TimerHandler() { a_ = a; }
protected:
	virtual void expire(Event *e);
	DTSNCCCacheAgent *a_;
};

class DTSNCCCacheAgent : public Agent {
public:
	DTSNCCCacheAgent(NDtsnCache*);
	void recv(Packet* pkt, Handler*);
	void reset();
	void forward();
	virtual void timeout();
	virtual void repair_timeout();
	int command(int argc, const char*const* argv);
	void calcNormProb();
	void shedPackets(int sessionNumber, int seqno);
	char *get_bitmap_string(int *NACKbitmap, int cwnd);
	int allowedSeqNo(int seqno, int window);
	void repair_hbh(Packet *);
	int inCache(Packet *);
	int update(int seqno, int numBytes);
	void resize_buffers(int sz);

protected:
	NDtsnCache* cacheBuffer_;
	char tbuf[100];
	FILE *tFile;
	int cacheSize_;
	double cachingWeight_[100];
	int cachelen_[100];
	int sessionActive_[100];
	double cachingProb_[100];
	double normProb_[100];
	int num_slots_[100];
	int caching_prob_;
	double in_info_rate_;
	double out_info_rate_;
	double last_received_;
	int enableRepeater_[100];
	int revnexthop_[100];
	int cacheMode_;					// 0=static, 1=dynamic
	int rpending_;
	int maxseqno_;
	int maxseen_;
	int *seen_;
	int wndmask_;
	int next_;
	int is_dup_;
	int srcAddr[50];
	int repair_enabled_;
	int *ackseqno_;
	int lastack_;
	int cumack_;

	/* Timers */
	DTSNCCForwardTimer forward_timer_;
	DTSNCCRepairTimer repair_timer_;
	double repair_timeout_;
	int timer_active_;
	int missingPkts[64];
	int numMissingPkts;
	int repair_seqno_;
	int endseqno_[100];
	int nextseqno_[100];
	int highestseqno_[100];
};

#endif

