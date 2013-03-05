#include <flags.h>
#include <ip.h>
#include <random.h>
#include <string.h>
#include <stat.h>
#include <string.h>
#include <stdlib.h>
#include "dtsncc-cache.h"

//#define DEBUGCACHE
//#define RNACK
//#define QLIMIT  1
//#define ACKGEN
//#define RNACK_PRIO

//#define INTREP
#define REPTO  0.5

#define MWS 64
#define MWM (MWS-1)

static class DTSNCCCacheAgentClass : public TclClass {
public:
	DTSNCCCacheAgentClass() : TclClass("Agent/DTSNCCCache") {}
	TclObject* create(int, const char*const*) {
		return (new DTSNCCCacheAgent(new NDtsnCache));
	}
} class_dtsncc_cache;

DTSNCCCacheAgent::DTSNCCCacheAgent(NDtsnCache* cache) : Agent(PT_DTSNCC),
	cacheBuffer_(cache), forward_timer_(this), cacheMode_(0), repair_timer_(this),
	last_received_(0), next_(0), maxseen_(0), wndmask_(MWM), rpending_(0), lastack_(0),
	timer_active_(0), cumack_(0), maxseqno_(-1)
{
	seen_ = new int[MWS];
	memset(seen_, 0, (sizeof(int) * (MWS)));
	ackseqno_ = new int[4000];
	memset(ackseqno_, 0, (sizeof(int) * (4000)));
	memset(nextseqno_, 0, (sizeof(int) * (100)));
	memset(highestseqno_, -1, (sizeof(int) * (100)));
	bind("repair_timeout_", &repair_timeout_);
	bind("repair_enabled_", &repair_enabled_);

/* initialization */
	int i;

	for (i=0; i<100; i++)
	{
		cachelen_[i] = 0;
		sessionActive_[i] = 0;
		normProb_[i] = 0.0;
		cachingProb_[i] = 0.0;
		num_slots_[i] = 0;
	}
}

void DTSNCCCacheAgent::calcNormProb()
{
	int i;
	double totalProb = 0;
	int numActive = 0;
	int sessionNumActive = 0;

	for (i=1; i<20; i++) {
		if (sessionActive_[i]==1) {
		  ++numActive;
		  sessionNumActive = i;
		  totalProb += (double)cachingWeight_[i];
		  }
		//if (sessionActive_[i]) printf("session: %d cachingWeight: %f slot: %d\n", i, cachingWeight_[i]);
		}
		//printf("totalWeight: %f\n", totalProb);
	if (numActive==1 && cachingWeight_[sessionNumActive]!=0) {
	  	totalProb=100;
	  	normProb_[sessionNumActive]=1;
	  	num_slots_[sessionNumActive] = normProb_[sessionNumActive]*cacheSize_;
	  	#ifdef DEBUGCACHE1
		printf("%f Node %d session: %d cachingWeight: %.2f totalWeight: %.2f normProb: %.2f slots: %d cache: %d\n", NOW, addr(), sessionNumActive, cachingWeight_[sessionNumActive], totalProb, normProb_[sessionNumActive], num_slots_[sessionNumActive], cacheSize_);
		#endif
	}

  	else if (numActive>1 && totalProb>0) {
		for (i=1; i<20; i++) {
		  	if (sessionActive_[i]) {
				normProb_[i] = cachingWeight_[i]/(double)totalProb;
				num_slots_[i] = normProb_[i]*cacheSize_;
				#ifdef DEBUGCACHE
				printf("Node %d session: %d cachingWeight: %.2f totalWeight: %.2f normProb: %.2f slots: %d cache: %d\n", addr(), i, cachingWeight_[i], totalProb, normProb_[i], num_slots_[i], cacheSize_);
				#endif
			}
		}
	}
}

int DTSNCCCacheAgent::allowedSeqNo(int seqno, int window)
{
  int start=0;
  int end=0;
  int cs15start[]={0,15,10,5};
  int cs15end[]={14,9,4,19};
  int index, result;

  if (cacheSize_==0) return 0;
  if (window<cacheSize_) return 1;
  if (cacheSize_==1)  {
	//double tmp=Random::uniform(0.0,1.0);
	//if (tmp>0.5) return 0;
	//else return 1;
	if (seqno==addr()) result = 1;
	else result = 0;
	}

  //if (DTSN_CACHE_SIZE==1) {
  //	double rand = randNum.uniform(0,1);
  //	if (rand>0.5) return 1;
  //	else return 0;
  //	}
  if (cacheSize_!=15) {
    if (addr() <= 90) {
    	if (addr() < 10) start = (addr() -1)%(window/cacheSize_)*cacheSize_;
    	else start = (addr()/10 -1)%(window/cacheSize_)*cacheSize_;
    }
	else start = (addr()-90-1)%(window/cacheSize_)*cacheSize_;
	//start = (addr()-1)%(window/cacheSize_)*cacheSize_;
    end = start + cacheSize_ -1;
    if (seqno>=start && seqno<=end) result = 1;
    else result = 0;
    }
  else {
    index=(addr()-1)%4;
    start = cs15start[index];
    end = cs15end[index];
    if (end > start) {
      if (seqno>=start && seqno<=end) result = 1;
      else result = 0;
      }
    else {
      if ((seqno>=start && seqno<=19) || (seqno>=0 && seqno<=end)) result = 1;
      else result = 0;
      }
    }
  //printf ("Node: %d seqno: %d start: %d end: %d result: %d\n", addr(), seqno, start, end, result);
  return result;
}

void DTSNCCCacheAgent::shedPackets(int sessionNumber, int seqno)
{
	Packet *p;
	int i;

	if (cacheBuffer_->length()) {
	if (tFile!=NULL) fprintf(tFile,"%f buflen: %d\n", NOW, cacheBuffer_->length() );
	for (i=cacheBuffer_->length()-1; i>=0 ;i--) {
	  	p = cacheBuffer_->lookup(i);
   	if (p!=NULL) {
    	hdr_dtsncc *th = HDR_DTSNCC(p);
    	if ( th->snum() == sessionNumber && th->seqno() <= seqno ) {
    		--cachelen_[sessionNumber];
    		if (cachelen_[sessionNumber] < 0)
    			cachelen_[sessionNumber] = 0;
			cacheBuffer_->remove(p);
    		if (tFile!=NULL)
				fprintf(tFile,"%f \t%d \t%d \tremoved len: %d %d\n", NOW, th->snum(), th->seqno(), cachelen_[sessionNumber], cacheBuffer_->length());
				//printf("%8d %8d %8d %8d removed len: %d\n", (int)(1000000*Scheduler::instance().clock()), getDtsnSessionNumber(p), hdr->size_, dtsnh->seqno, cachelen[sessionNumber]);
				//#endif
    			//count++;
    		}
    	}
   	}
   }
  //if (count) printf("%d packets removed from cache node:%d session:%d cachelen: %d\n", count, addr(), sessionNumber, cacheBuffer->length());

	// clear rpending_ flag
	if (rpending_ && repair_seqno_ < seqno)
		rpending_ = 0;

	sessionActive_[sessionNumber] = 0;
	calcNormProb();
}

char *DTSNCCCacheAgent::get_bitmap_string(int *NACKbitmap, int cwnd)
{
	int i;
	static char bitmap[100];

	for (i=0; i<cwnd; i++) {
		if (NACKbitmap[i]) bitmap[i] = '1';
		else bitmap[i] = '0';
	}
	bitmap[i] = '\0';
	return (bitmap);
}

int DTSNCCCacheAgent::inCache(Packet* pkt)
{
	hdr_dtsncc *th = HDR_DTSNCC(pkt);
	int i;
	Packet *p;

	if (cacheBuffer_->length()) {
		for (i = 0; i < cacheBuffer_->length(); i++) {
			p = cacheBuffer_->lookup(i);
			if (p!=NULL) {
				hdr_dtsncc *thc = HDR_DTSNCC(p);
				if (thc->snum()==th->snum() && thc->seqno()==th->seqno())
					return 1;
			}
		}
		return 0;
	}
	else return 0;
}

void DTSNCCCacheAgent::repair_hbh(Packet* pkt)
{
	int tmp[64], i;
	bool just_marked_as_seen = FALSE;
	is_dup_ = FALSE;

	Packet* npkt = allocpkt();
	hdr_dtsncc *thn = HDR_DTSNCC(npkt);
	hdr_dtsncc *th = HDR_DTSNCC(pkt);
	hdr_ip *iphn = HDR_IP(npkt);
	hdr_ip *iph = HDR_IP(pkt);
	hdr_cmn *ch = HDR_CMN(pkt);
	hdr_cmn *chn = HDR_CMN(npkt);
	iphn->flowid() = iph->flowid();
	iphn->sport() = th->snum();
	iphn->dport() = th->snum();
	int sessionNumber = th->snum();

	if (th->seqno() == nextseqno_[sessionNumber]) {	// in-order
		//printf("snum: %d next: %d highest: %d\n", sessionNumber, nextseqno_[sessionNumber], highestseqno_[sessionNumber]);
		nextseqno_[sessionNumber] = highestseqno_[sessionNumber] + 1;
		}
	else if ( (nextseqno_[sessionNumber] < endseqno_[sessionNumber]) && th->seqno() > highestseqno_[sessionNumber]  ) {
		#ifdef RNACK_PRIO
		thn->highprio() = 1;
		#endif
		iphn->saddr() = addr();
		//iphn->daddr() = iph->saddr();
		iphn->daddr() = ch->prev_hop();
		thn->ts() = NOW;
		thn->snum() = th->snum();
		thn->saddr() = addr();
	 	thn->daddr() = th->saddr();
		thn->seqno() = nextseqno_[sessionNumber];
		thn->nack() = 0;
		thn->data() = 0;
		thn->ear() = 0;
		thn->rnack() = 1;
		thn->cum_ack() = 0;
		//fprintf(tFile, "%f RNACK %8d saddr:%d sport:%d daddr:%d dport:%d\tOut-of-order\n", NOW, th->seqno(), iphn->saddr(), iphn->sport(), iphn->daddr(), iphn->dport());
		if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tRNACK sent next: %d \n", NOW, thn->snum(), thn->seqno(), nextseqno_[sessionNumber]);
		repair_seqno_ = nextseqno_[sessionNumber];
		rpending_ = 1;
		//#ifdef RNACK
		if (repair_enabled_) Agent::send(npkt,0);
		//#endif
		}
		/*
		#ifdef INTREP
		fprintf(tFile, "%f %8d \tOut-of-order next:%d\n", NOW, th->seqno(), next_);
		if (th->seqno() > maxseen_) {
			int i;
			for (i = maxseen_ + 1; i < th->seqno(); ++i)
				seen_[i & wndmask_] = 0;
			maxseen_ = th->seqno();
			seen_[maxseen_ & wndmask_] = 1;
			seen_[(maxseen_ + 1) & wndmask_] = 0;
			}
		int next = next_;
		if (th->seqno() < next) {
			is_dup_ = TRUE;
			}

		if (th->seqno() >= next && th->seqno() <= maxseen_) {
			if (seen_[th->seqno() & wndmask_] && !just_marked_as_seen) {
				is_dup_ = TRUE;
				}
			seen_[th->seqno() & wndmask_] = 1;
			while (seen_[next & wndmask_]) {
				++next;
				}
			next_ = next;
			}
		#endif
		*/
	Packet::free(pkt);
}

void DTSNCCCacheAgent::recv(Packet* pkt, Handler*)
{
	hdr_dtsncc *th = HDR_DTSNCC(pkt);
	hdr_ip *iph = HDR_IP(pkt);

	int sessionNumber = th->snum();
	double delta;
	int numToDeliver;
	int numBytes = hdr_cmn::access(pkt)->size();

	if (th->data()) {
		/* cache the packet */
		Packet *cachepkt;
		cachepkt = allocpkt();
		cachepkt = pkt->copy();
		hdr_dtsncc *thc = HDR_DTSNCC(cachepkt);
		srcAddr[th->snum()] = iph->saddr();

		if (last_received_==0) {
			delta = 0;
			in_info_rate_ = 0;
			}
		else {
			delta = NOW - last_received_;
			if (delta) in_info_rate_ = 1.0/delta;
			}
		last_received_ = NOW;

		// register endseqno_
		endseqno_[sessionNumber] = th->endseqno();

		//if (tFile!=NULL)
			//fprintf(tFile,"%f %8d %8d \tINFO RATE %f %f\n", NOW, thc->snum(), thc->seqno(), delta, in_info_rate_);

		if ( sessionActive_[sessionNumber] == 0 )  {
			//printf("session:%d\n", sessionNumber);
			sessionActive_[sessionNumber] = 1;
			enableRepeater_[sessionNumber] = 0;
			calcNormProb();
			}

		if (th->seqno() > highestseqno_[sessionNumber])
			highestseqno_[sessionNumber] = th->seqno();

		if (tFile!=NULL)
			fprintf(tFile,"%f \t%d \t%d \tDATA highest: %d \n", NOW, th->snum(), th->seqno(), highestseqno_[sessionNumber]);

		// Single repair
		if (repair_enabled_) {
			if (!rpending_)
				repair_hbh(pkt);
			else if (rpending_ && th->seqno() == repair_seqno_) {
				rpending_ = 0;
				}
			}

		// update cache window
		//numToDeliver = update(th->seqno(), numBytes);
		//if (th->maxseqno() > maxseqno_)
			//maxseqno_ = th->maxseqno();
		//next_ = maxseen_+1;

		if ( !inCache(pkt) && (cachelen_[sessionNumber] < cacheSize_) ) {
		//if (cachelen_[sessionNumber] < normProb_[sessionNumber]*cacheSize_ && (allowedSeqNo(th->seqno(), th->window()) || th->cached())  ) {
		//printf("DATA seqno:%d session:%d size:%.0f cachelen:%d\n", th->seqno(), sessionNumber, normProb_[sessionNumber]*cacheSize_, cachelen_[sessionNumber]);
		//printf("Cache Node: %d Session: %d \n", addr(), sessionNumber);

		/*
		// activate the cache watchdog timer
		if (!timer_active_) {
			//repair_timer_.sched(repair_timeout_);
			timer_active_ = 1;
			if (tFile!=NULL)
				fprintf(tFile,"%f \t%d \t%d \tTIMER activated len: %d total: %d\n", NOW, thc->snum(), thc->seqno(), cachelen_[sessionNumber], cacheBuffer_->length());
			}
		*/

		cacheBuffer_->put(cachepkt);
		cachelen_[sessionNumber]++;
		if (tFile!=NULL)
			fprintf(tFile,"%f \t%d \t%d \tCACHING len: %d total: %d rpending: %d next: %d\n", NOW, thc->snum(), thc->seqno(), cachelen_[sessionNumber], \
					cacheBuffer_->length(), rpending_, nextseqno_[sessionNumber] );;

			}

		//#ifdef RNACK
		//#endif

		}

	else if (th->nack()) {

		Packet *fbpkt, *cachepkt;
		Packet *p;
		fbpkt = allocpkt();
		fbpkt = pkt->copy();
		char metricID[20];
		int rtxCount=0, found=0, new_numholes=0;

		hdr_dtsncc *thf = HDR_DTSNCC(fbpkt);
		hdr_cmn *chf = HDR_CMN(fbpkt);
		hdr_ip* ipf = HDR_IP(fbpkt);

		chf->direction() = hdr_cmn::DOWN;
		chf->ptype() = PT_DTSNCC;
		thf->seqno() = th->seqno();
		thf->data() = 0;
		thf->nack() = 1;
		thf->ear() = 0;
		thf->cum_ack() = th->cum_ack();
		ipf->sport() = 0;
		ipf->dport() = sessionNumber;
		ipf->saddr() = th->saddr();
		ipf->daddr() = th->daddr();

		int i, j=0;
		int tmp[64], lostseqno, n, hits=0;
	 	char NACK_list[100] = "\0";
	 	char buffer[10];
	 	int NACK_list_[64];
 	 	memset(NACK_list_, 0, (sizeof(int) * (64)));
 	 	int mod_NACK_list_[64];
 	 	memset(mod_NACK_list_, 0, (sizeof(int) * (64)));

		for (i = 0; i < th->num_holes(); i++) {
 			sprintf(buffer, " %d ", th->NACK_list_[i]);
 			strcat(NACK_list, buffer);
			}
		if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tNACK received holes=%d [%s] cumACK: %d\n", NOW, th->snum(), th->seqno(), th->num_holes(), NACK_list, th->cum_ack() );

		// retransmit cache packets if timer is active
		//if (timer_active_) {
		if (cacheBuffer_->length() && th->num_holes()) {
			for (i = 0; i < th->num_holes(); i++) {
				found = 0;
  				for (n = 0; n < cacheBuffer_->length(); n++) {
    				p = cacheBuffer_->lookup(n);
    				if (p!=0) {
    					hdr_dtsncc *thc = HDR_DTSNCC(p);
    					hdr_ip *ipc = HDR_IP(p);
    					lostseqno = th->NACK_list_[i];
    					//printf("Len (%d):%8d %8d %8d %8d %8d\n", addr(), cacheBuffer_->length(), seqno, thc->seqno(), thc->snum(), sessionNumber);
						if ( thc->seqno() == lostseqno && thc->snum() == th->snum() ) {
							++hits;
							found = 1;
  							cachepkt = allocpkt();
    						cachepkt = p->copy();
    						hdr_cmn* ch = HDR_CMN(cachepkt);
    						hdr_dtsncc* th_rtx = HDR_DTSNCC(cachepkt);
    						hdr_ip* iph = HDR_IP(cachepkt);

    						ch->direction() = hdr_cmn::DOWN;
    						th_rtx->seqno() = thc->seqno();
    						th_rtx->data() = 1;
    						th_rtx->cached() = 1;
    						th_rtx->rtx() = 1;
    						th_rtx->ear() = 0;
							th_rtx->ts() = NOW;
							th_rtx->rtx_src() = addr();

    						iph->dport() = sessionNumber;
    						iph->sport() = addr();
    						iph->daddr() = th->saddr();

    						if (tFile!=NULL)
    							fprintf(tFile, "%f \t%d \t%d \tCACHE HIT src: %d dst: %d\n", NOW, th_rtx->snum(), th_rtx->seqno(), iph->saddr(), iph->daddr());

    						fprintf(tFile, "%f \t%d \t%d \t%d DATA sent data:%d cached:%d rtx:%d\n", NOW, th_rtx->snum(), th_rtx->seqno(), ch->size(), th_rtx->data(), th_rtx->cached(), th_rtx->rtx() );
	    					sprintf(metricID, "%02d%02d", sessionNumber, addr());
	    					//if (tFile!=NULL) fprintf(tFile,"%f %8d %8d src: %d dst: %d \tCache hit\n", NOW, sessionNumber, th_rtx->seqno(), addr(), iph->daddr());
	    					Stat::put("cache_hits", atoi(metricID), 1);
							//Stat::put("dtsn_cache_hits_d", atoi(metricID), 1);
	    					Stat::put("cache_hits_total", sessionNumber, 1);
	    					//#endif
	    					//found = 1;
	    					//printf ("Node %d sending cached packet seqno: %d c_flag: %d\n", addr(), newdata->seqno(), newdata->cached());
	    					//if (dtsnh_rtx->flags.data) Stat::put("pkt_tx_cost", dtsnh_rtx->seqno, 1);
	    					Agent::send(cachepkt, 0);
	    					break;
    						}
    					}
					}
  				if (!found) {
  					// add to modified NACK list
  					mod_NACK_list_[j] = th->NACK_list_[i];
  					++j;
  					++new_numholes;
  					}
				}

			memcpy(thf->NACK_list_, mod_NACK_list_, new_numholes*sizeof(int));
			thf->num_holes() = new_numholes;
			char mod_NACK_list[100] = "\0";
			char mod_buffer[10];
			for (i = 0; i < thf->num_holes(); i++) {
			 	sprintf(mod_buffer, " %d ", thf->NACK_list_[i]);
			 	strcat(mod_NACK_list, mod_buffer);
				}
			if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tmod NACK holes=%d [%s] cumACK: %d\n", NOW, thf->snum(), thf->seqno(), thf->num_holes(), mod_NACK_list, thf->cum_ack() );
			Agent::send(fbpkt,0);
			}

		else {
			// send NACK packet as is
			if (th->num_holes()) {
				memcpy(thf->NACK_list_, th->NACK_list_, th->num_holes()*sizeof(int));
				thf->num_holes() = th->num_holes();
				char mod_NACK_list[100] = "\0";
				char mod_buffer[10];
				for (i = 0; i < thf->num_holes(); i++) {
					sprintf(mod_buffer, " %d ", thf->NACK_list_[i]);
					strcat(mod_NACK_list, mod_buffer);
					}
				if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tmod NACK holes=%d [%s] cumACK: %d\n", NOW, thf->snum(), thf->seqno(), thf->num_holes(), mod_NACK_list, thf->cum_ack() );
				}
			else {
				thf->nack() = 0;
				thf->ack() = 1;
				if (tFile!=NULL) fprintf(tFile, "%f \t%d \t%d \tmod ACK holes=%d cumACK: %d\n", NOW, thf->snum(), thf->seqno(), thf->num_holes(), thf->cum_ack() );
				}
			Agent::send(fbpkt,0);
			}
		//}

		// purge cache
		if (cacheBuffer_->length()) {

			//for (n = 0; n < cacheBuffer_->length(); n++) {
			for (n=cacheBuffer_->length()-1; n>=0 ;n--) {
				int inNACKList = 0;
				p = cacheBuffer_->lookup(n);
				if (p!=0) {
					hdr_dtsncc *thc = HDR_DTSNCC(p);
					hdr_ip *ipc = HDR_IP(p);

					for (i = 0; i < th->num_holes(); i++) {
						if (thc->seqno() == th->NACK_list_[i] && thc->snum() == th->snum() && thc->seqno() <= th->cum_ack()) {
							inNACKList = 1;
							break;
							}
						}

					if (!inNACKList) {
						--cachelen_[th->snum()];
			    		if (cachelen_[th->snum()] < 0) cachelen_[th->snum()] = 0;
						cacheBuffer_->remove(p);
			    		if (tFile!=NULL)
							fprintf(tFile,"%f \t%d \t%d \tremoved len: %d of %d\n", NOW, thc->snum(), thc->seqno(), cachelen_[th->snum()], cacheBuffer_->length());

			    		// clear rpending_ flag
			    		if (rpending_ && repair_seqno_== thc->seqno()) {
			    			rpending_ = 0;
			    			if (tFile!=NULL)
			    				fprintf(tFile,"%f \t%d \t%d \tPending flag cleared\n", NOW, thc->snum(), thc->seqno() );
			    			nextseqno_[sessionNumber] = highestseqno_[sessionNumber] + 1;
							}
						}
					}
				}
			}

	}

	else if (th->ear()) {

		if (tFile!=NULL)
			fprintf(tFile,"%f %8d %8d \tEAR received src: %d \n", NOW, th->snum(), th->seqno(), iph->saddr());

		Packet *fbpkt;
		fbpkt = allocpkt();
		fbpkt = pkt->copy();

		hdr_dtsncc *thf = HDR_DTSNCC(fbpkt);
		hdr_cmn *chf = HDR_CMN(fbpkt);
		hdr_ip* ipf = HDR_IP(fbpkt);

		chf->direction() = hdr_cmn::DOWN;
		chf->ptype() = PT_DTSNCC;
		thf->seqno() = th->seqno();
		thf->data() = 0;
		thf->nack() = 0;
		thf->ear() = 1;
		ipf->sport() = 0;
		ipf->dport() = sessionNumber;
		ipf->saddr() = th->saddr();
		ipf->daddr() = th->daddr();
		//Agent::send(fbpkt,0);
		}

//#ifdef RNACK
	else if (th->rnack()) {

		if (tFile!=NULL)
			fprintf(tFile, "%f \t%d \t%d \tRNACK received\n", NOW, th->snum(), th->seqno() );

	Packet *cachepkt, *p;
	int i, n, hits, found=0;
	char metricID[20];

	if (cacheBuffer_->length()) {
		for (n=0; n<cacheBuffer_->length(); n++) {
				p = cacheBuffer_->lookup(n);
  				if (p!=0) {
  					hdr_dtsncc *thc = HDR_DTSNCC(p);
					if (thc->seqno()==th->seqno() && thc->snum()==th->snum()) {
						hits++;
						cachepkt = allocpkt();
   						cachepkt = p->copy();
   						hdr_cmn* ch = HDR_CMN(cachepkt);
   						hdr_dtsncc* th_rtx = HDR_DTSNCC(cachepkt);
   						hdr_ip* iphc = HDR_IP(cachepkt);

   						ch->direction() = hdr_cmn::DOWN;
   						th_rtx->seqno() = th->seqno();
   						th_rtx->data() = 1;
   						th_rtx->rtx() = 0;
   						th_rtx->cached() = 1;
						th_rtx->saddr() = addr();
   						th_rtx->ear() = 0;
						th_rtx->ts() = NOW;
						th_rtx->rtx_src() = addr();
						#ifdef RNACK_PRIO
						th_rtx->highprio() = 1;
						#endif
   						//iphc->sport() = 0;
   						iphc->dport() = sessionNumber;
   						iphc->daddr() = thc->daddr();
    					//fprintf(tFile, "%f RNACK reply snum: %d seqno: %d dst: %d %d\n", NOW, sessionNumber, th_rtx->seqno(), iphc->daddr(), iphc->dport());
    					sprintf(metricID, "%02d%02d", sessionNumber, addr());
    					if (tFile!=NULL) fprintf(tFile,"%f \t%d \t%d \tRNACK CACHE HIT src: %d dst: %d \n", NOW, sessionNumber, th_rtx->seqno(), addr(), iphc->daddr());
	    				Stat::put("dtsn_cache_hits", atoi(metricID), 1);
						Stat::put("dtsn_cache_hits_d", atoi(metricID), 1);
	    				Stat::put("total_cache_hits", sessionNumber, 1);
	    				found = 1;
	    				Agent::send(cachepkt, 0);
	    				break;
    				}
    			}
			}
		}
	}
//#endif


	else if (th->eot()) {
		//repair_timer_.cancel();
		}

	else if (th->ack()) {

		Packet *fbpkt, *cachepkt;
		Packet *p;
		fbpkt = allocpkt();
		fbpkt = pkt->copy();
		char metricID[20];
		int rtxCount=0, found=0, new_numholes=0;

		hdr_dtsncc *thf = HDR_DTSNCC(fbpkt);
		hdr_cmn *chf = HDR_CMN(fbpkt);
		hdr_ip* ipf = HDR_IP(fbpkt);

		chf->direction() = hdr_cmn::DOWN;
		chf->ptype() = PT_DTSNCC;
		thf->seqno() = th->seqno();
		thf->data() = 0;
		thf->nack() = 0;
		thf->ack() = 1;
		thf->ear() = 0;
		thf->cum_ack() = th->cum_ack();
		ipf->sport() = 0;
		ipf->dport() = sessionNumber;
		ipf->saddr() = th->saddr();
		ipf->daddr() = th->daddr();

		if (tFile!=NULL)
			fprintf(tFile, "%f \t%d \t%d \tACK received\n", NOW, th->snum(), th->seqno() );
		shedPackets(th->snum(), th->seqno());

		//if (tFile!=NULL)
		//	fprintf(tFile, "%f \t%d \t%d \tACK holes=%d cumACK: %d\n", NOW, thf->snum(), thf->seqno(), thf->num_holes(), thf->cum_ack() );

		//Agent::send(fbpkt,0);
		}

	Packet::free(pkt);
}

void DTSNCCCacheAgent::reset()
{
}

void DTSNCCCacheAgent::resize_buffers(int sz) {
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

int DTSNCCCacheAgent::update(int seq, int numBytes)
{

	bool just_marked_as_seen = FALSE;
	is_dup_ = FALSE;

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

void DTSNCCCacheAgent::forward()
{
	int n;
	Packet *p, *cachepkt;

	if (cacheBuffer_->length()) {
		for (n=0; n<cacheBuffer_->length(); n++) {
        	p = cacheBuffer_->lookup(n);
        	if (p!=0) {
        		//printf("Len (%d):%8d %8d %8d %8d %8d\n", addr(), cacheBuffer_->length(), seqno, thc->seqno(), thc->snum(), sessionNumber);
				hdr_dtsncc* th = HDR_DTSNCC(p);
      			cachepkt = allocpkt();
        		cachepkt = p->copy();
        		hdr_cmn* ch = HDR_CMN(cachepkt);
        		hdr_dtsncc* th_rtx = HDR_DTSNCC(cachepkt);
        		hdr_ip* iph = HDR_IP(cachepkt);

        		ch->direction() = hdr_cmn::UP;
        		th_rtx->seqno() = th->seqno();
        		th_rtx->data() = 1;
        		th_rtx->ear() = 0;
        		iph->sport() = 0;
        		iph->dport() = th->snum();
        		iph->daddr() = th->daddr();
        		//#ifdef DEBUGPRINT
        		//if (tFile!=NULL)
				printf("%f Forwarding snum:%d size:%d node:%d seqno:%d dst: %d\n", NOW, th_rtx->snum(), ch->size(), addr(), th_rtx->seqno(), iph->daddr());
				//sprintf(metricID, "%02d%02d", sessionNumber, addr());
				//if (tFile!=NULL) fprintf(tFile,"%f %8d %8d src: %d dst: %d Cache hit\n", NOW, sessionNumber, th_rtx->seqno(), addr(), iph->daddr());
				//Stat::put("dtsn_cache_hits", atoi(metricID), 1);
				//Stat::put("total_cache_hits", sessionNumber, 1);
				//#endif
				//found = 1;
				//printf ("Node %d sending cached packet seqno: %d c_flag: %d\n", addr(), newdata->seqno(), newdata->cached());
				//if (dtsnh_rtx->flags.data) Stat::put("pkt_tx_cost", dtsnh_rtx->seqno, 1);
				Agent::send(cachepkt, 0);
        		}
			}
		}

}

int DTSNCCCacheAgent::command(int argc, const char*const* argv)
{

	if (strcmp(argv[1], "set_trace_filename") == 0) {
		strcpy(tbuf, argv[2]);
		tFile = fopen(tbuf, "w");
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_cache_size") == 0) {
		cacheBuffer_->maxlen_ = atoi(argv[2]);
		//printf("maxlength %d\n", cacheBuffer_->maxlength());
		cacheSize_ = atoi(argv[2]);
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_cache_weight") == 0) {
		cachingWeight_[atoi(argv[2])] = atof(argv[3]);
		//printf("Session: %d Weight: %f\n", atoi(argv[2]), cachingWeight_[atoi(argv[2])]);
		return (TCL_OK);
	}

	if (strcmp(argv[1], "set_repair") == 0) {
		repair_enabled_ = atoi(argv[2]);
		return (TCL_OK);
		}

	return (Agent::command(argc, argv));
}

void DTSNCCCacheAgent::timeout()
{
	forward();
	forward_timer_.resched(0.2);
}

void DTSNCCForwardTimer::expire(Event*)
{
	a_->timeout();
}

void DTSNCCCacheAgent::repair_timeout()
{

	Packet* pkt = allocpkt();
	hdr_cmn* ch = HDR_CMN(pkt);
	hdr_dtsncc* th = HDR_DTSNCC(pkt);
	hdr_ip* iph = HDR_IP(pkt);

	char NACK_list[100] = "\0";

	//printf("Link timer\n");
	//iph->daddr() = IP_BROADCAST;
	//iph->dport() = 3000;
	//ch->next_hop() = IP_BROADCAST;
	//th->etx() = 1;

	if (tFile!=NULL)
		fprintf(tFile,"%f \tTIMER fired cachelen: %d next_: %d maxseen: %d\n", NOW, cacheBuffer_->length(), next_, maxseen_);

	numMissingPkts = 0;
	char buffer[10];
	memset (missingPkts, 0, sizeof(int)*64);
	int next = next_;
 	int maxseq;

 	if ((maxseqno_ - maxseen_) < 5)
 		maxseq = maxseqno_;
 	else
 		maxseq = maxseen_;

	while (next <= maxseq) {
		//if (tFile!=NULL) fprintf (tFile, "next_: %d maxseen_: %d wndmask_: %d seen_: %d\n", next, maxseen_, wndmask_, sizeof(seen_));
		if (seen_[next & wndmask_] == 0) {
			missingPkts[numMissingPkts] = next;
			++numMissingPkts;
			sprintf(buffer, " %d ", next);
			strcat(NACK_list, buffer);
			//printf ("Missing: %d\n", next);
			}
		++next;
		}

	if ( numMissingPkts > 0 ) {
		//if (tFile!=NULL) fprintf (tFile, "%d missing packets\n", numMissingPkts);
		//printf ("Missing packets node: %d\n", addr());
		iph->flowid() = 1;
		iph->sport() = 1;
		iph->dport() = 1;
		iph->saddr() = addr();
		iph->daddr() = srcAddr[1];
		th->ts() = NOW;
		th->snum() = 1;
		th->saddr() = addr();
	 	th->daddr() = srcAddr[1];
		th->seqno() = next_;
		th->nack() = 1;
		th->data() = 0;
		th->ear() = 0;
		th->num_holes() = numMissingPkts;
		memcpy(th->NACK_list_, missingPkts, numMissingPkts*sizeof(int));
		if (tFile!=NULL)
			fprintf(tFile, "%f \tNACK sent holes=%d [%s] saddr:%d sport:%d daddr:%d dport:%d\t\n", NOW, th->num_holes(), NACK_list, iph->saddr(), iph->sport(), iph->daddr(), iph->dport());
		send(pkt,0);
		}

	repair_timer_.resched(repair_timeout_);
}

void DTSNCCRepairTimer::expire(Event*)
{
	a_->repair_timeout();
}

