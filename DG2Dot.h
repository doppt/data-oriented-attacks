#ifndef DG_2_DOT_H_
#define DG_2_DOT_H_

#include <iostream>
#include <fstream>
#include <set>

#include "DependenceGraph.h"
#include "analysis/DFS.h"

 

#include "./dop_define.h"
#include <llvm/Support/Debug.h>
#include <boost/algorithm/string.hpp>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/classification.hpp> // Include boost::for is_any_of
#include <boost/algorithm/string/split.hpp> // Include for boost::split
#include <boost/lexical_cast.hpp>

 


std::map<std::string, std::set<std::string> > callgraph;
std::map < std::string, std::string > InsLocMap;
std::string current_funcname;  //when matching in InsLocMap

//#define INTERPROCEDURE_ANALYSIS  //enable the inter-procedure analysis

#undef INTERPROCEDURE_ANALYSIS

int global_dopbr_count=0;

std::string trim(const std::string& str)
{
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

struct DopGadget {
    std::string gadget;
    std::string location;
    std::string function;
    std::string ptr;
    std::string value;
};

struct FuncArg {
    std::string funcname;
    std::vector<std::string> arglist;
    std::string filename;
};

struct AttackPoint {
    AttackPoint():line(0),funcname(""), variable(""),filename("") { }
    int line;
    std::string funcname;
    std::string variable;
    std::string filename;
};

struct vertex {

	//typedef pair<int,vertex*> ve;
    //vector<ve> adj; //cost of edge, destination vertex

    std::set<std::string> outgoingset;
    std::set<std::string> incomingset;
    std::string nodeid;
    std::string inst;
    std::string loc;
    std::string bbid;

    vertex(std::string n, std::string s, std::string l):nodeid(n), inst(s),loc(l) {}
    vertex(std::string n, std::string s, std::string l, std::string b):nodeid(n), inst(s),loc(l),bbid(b) {}
};

struct Event {
    std::string efunc;
    int efuncId;
    bool flag;
};


struct EventAction {
    std::string afunc;
    int afuncId;
    std::vector<Event> eventlist;
};

class MyBBDependency {
public:
	 std::string brkbbid;
	 std::string brknodeid;
	 std::string brkinst;
	 std::string brkloc;
	 std::string tobbid;
	 int label;
	 std::vector<vertex*> DDlist;   //allows duplicate items inside
};

class MyGraph {
	public:
		std::map<std::string, vertex*> vmap;

		bool addvertex(const std::string &nodeid, const std::string &inst, const std::string &loc)
		{

			auto itr = vmap.find(nodeid);
		    if(itr==vmap.end())
		    {
		        vertex *v;
		        v= new vertex(nodeid, inst, loc);
		        vmap[nodeid]=v;
		        return true;
		    }
		    else
		    {
		    		//std::cout<<"\nVertex already exists!\n";
		    		return false;
		    }
		}

		bool addvertex(const std::string &nodeid, const std::string &inst, const std::string &loc, const std::string &bbid)
		{

				auto itr = vmap.find(nodeid);
			    if(itr==vmap.end())
			    {
			        vertex *v;
			        v= new vertex(nodeid, inst, loc, bbid);
			        vmap[nodeid]=v;
			        return true;
			    }
			    else
			    {
			    		//std::cout<<"\nVertex already exists!\n";
			    		return false;
			    }
		}


		void addedge(const std::string& from_nodeid, const std::string& to_nodeid, const std::string& from_inst, const std::string& to_inst, const std::string& from_loc, const std::string& to_loc)
		{
			//find vertex already exist in the vmap first, if not, addvertex
			addvertex(from_nodeid, from_inst, from_loc);
			addvertex(to_nodeid, to_inst, to_loc);
			//find the from node
			vertex *f=(vmap.find(from_nodeid)->second);
			//insert the edge for the from node
			f->outgoingset.insert(to_nodeid);

			//find the to node
			f=(vmap.find(to_nodeid)->second);
			//insert the edge for the to node
			f->incomingset.insert(from_nodeid);
		}

		void addedge(const std::string& from_nodeid, const std::string& to_nodeid, const std::string& from_inst, const std::string& to_inst, const std::string& from_loc, const std::string& to_loc,  const std::string& from_bbid, const std::string& to_bbid)
		{
			//find vertex already exist in the vmap first, if not, addvertex
			addvertex(from_nodeid, from_inst, from_loc, from_bbid);
			addvertex(to_nodeid, to_inst, to_loc, to_bbid);
			//find the from node
			vertex *f=(vmap.find(from_nodeid)->second);
			//insert the edge for the from node
			f->outgoingset.insert(to_nodeid);

			//find the to node
			f=(vmap.find(to_nodeid)->second);
			//insert the edge for the to node
			f->incomingset.insert(from_nodeid);
		}


		std::string findidbyinst(const std::string& inst) {

			std::map<std::string, vertex*>::iterator it;

			for(it=vmap.begin(); it!=vmap.end(); ++it) {

				if ( it->second->inst == inst )
					return it->first;
			}
			return "";
		}
		
		std::string findinstbysubstr(const std::string& substr) {
			std::map<std::string, vertex*>::iterator it;
                        for(it=vmap.begin(); it!=vmap.end(); ++it) {

                                if ( it->second->inst.find( substr ) != std::string::npos )
                                        return it->second->inst;
                        }
                        return "";
                }

                std::string findinstbysubstrs(const std::string& substr1, const std::string& substr2) {
                        std::map<std::string, vertex*>::iterator it;
                        for(it=vmap.begin(); it!=vmap.end(); ++it) {

                                if ( it->second->inst.find( substr1 ) != std::string::npos && it->second->inst.find( substr2 ) != std::string::npos )
                                        return it->second->inst;
                        }
                        return "";
                }

		vertex* findvertexbyinst(const std::string& inst) {

			std::map<std::string, vertex*>::iterator it;

			for(it=vmap.begin(); it!=vmap.end(); ++it) {

				if ( it->second->inst == inst )
					return it->second;
			}
			return NULL;
		}

		vertex* findvertexbyid(const std::string& nodeid) {

			auto itr = vmap.find(nodeid);
			if(itr==vmap.end())
			{
				return NULL;
			}
			else
			{
				vertex *f=(itr->second);
				return f;
			}
		}

		vertex* findvertexbystring(const std::string& myvariable) {

			std::map<std::string, vertex*>::iterator it;

			for(it=vmap.begin(); it!=vmap.end(); ++it) {
				if ( it->second->inst.find(myvariable) != std::string::npos) {
					return it->second;
				}
			}
			return NULL;
		}
		void dumpallnodes(){

			std::map<std::string, vertex*>::iterator it;
                        for(it=vmap.begin(); it!=vmap.end(); ++it) {
				 
				if ( it->second->loc.size() < 5  ) {
					auto itr = InsLocMap.find(it->second->inst);
					if(itr!=InsLocMap.end() ) { 
						llvm::dbgs() << "[doplog] recover loc:" << itr->second << "\n";	
					}
				}
				 
                        }
		}		

};


//extern dg::MyGraph ddGraph;
MyGraph cdGraph;
MyGraph ddGraph;
MyGraph cfGraph;
std::vector<FuncArg> FunctionList;
//FuncArg

extern std::vector<MyBBDependency> MyBrkList;


namespace dg {
namespace debug {

enum dg2dot_options {
    PRINT_NONE      = 0, // print no edges
    PRINT_CFG       = 1 << 0,
    PRINT_REV_CFG   = 1 << 1,
    PRINT_DD        = 1 << 2,
    PRINT_REV_DD    = 1 << 3,
    PRINT_CD        = 1 << 4,
    PRINT_REV_CD    = 1 << 5,
    PRINT_CALL      = 1 << 6,
    PRINT_POSTDOM   = 1 << 7,
    PRINT_ALL       = ~((uint32_t) 0)
};

struct Indent
{
    int ind;
    Indent(int ind = 1):ind(ind) {}
    friend std::ostream& operator <<(std::ostream& os, const Indent& ind);
};

std::ostream& operator <<(std::ostream& os, const Indent& ind)
{
    for (int i = 0; i < ind.ind; ++i)
        os << "\t";

    return os;
}

template <typename NodeT>
class DG2Dot
{
    std::set<const typename DependenceGraph<NodeT>::ContainerType *> dumpedGlobals;
public:
    typedef typename NodeT::KeyType KeyT;
    
     
    bool is_analyzing_upstream=true;	
    bool upstream_dd=false;
    bool downstream_dd=false;
    std::queue<std::string> nodeQueueUp;  
    std::queue<std::string> nodeQueueDown;
    MyGraph ddGraphUp; //only keep the PT related inst, i.e, br or call
    MyGraph ddGraphDown;


   
    std::vector<DopGadget*> DopGadgetArray;
    std::string dopgadgetfilename;     //used as a filter to load relevant gadgets
    std::string rootfunc;

    int coarsegrained_br_count=0;
    int coarsegrained_call_count=0;
    bool is_coarsegrained_analysis =false;
    std::vector<std::string> coarsegrained_brset; 
    std::vector<std::string> coarsegrained_callset;
     

    DG2Dot<NodeT>(DependenceGraph<NodeT> *dg,
                  uint32_t opts = PRINT_CFG | PRINT_DD | PRINT_CD,
                  const char *file = NULL)
        : options(opts), dg(dg), file(file)
    {
        // if a graph has no global nodes, this will forbid trying to print them
        dumpedGlobals.insert(nullptr);
        reopen(file);


    }

 
   std::set<std::string> correlated_br_list;
   std::set<std::string> inter_correlated_br_list;

   void print_inst_set ( std::set<std::string> instSet ) {

   	for (auto inst : instSet) {
		llvm::dbgs() << "[doplog] printing, inst:" << inst << "\n";
	}
   
   }

    std::string get_inst_loc ( std::string inst ) {
	vertex* pvertex = ddGraph.findvertexbyinst( inst );
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] error, in get_inst_loc, can not find in ddGraph, inst:" << inst << "\n";
		return "";
	}
	else {
		return pvertex->loc;
	}
    }

    std::set<std::string> find_allbackward_dd( std::set<std::string> ddSet , bool is_counting = false , int &count = *(int*)0 ) { 
	 
	std::set<std::string> forward_ddSet;
	
	std::string brloc_str;

for (auto inst : ddSet) {
	std::queue<std::string> nodeQueue;  //store nodeid
	std::set<std::string> VisitedSet;  //to avoid loop

	vertex* pvertex = ddGraph.findvertexbyinst( inst );
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] error, in find_allbackward_dd, can not find in ddGraph, inst:" << inst << "\n";
		return forward_ddSet;			
        }

	//for counting br inst
	if ( is_counting == true ) {
		//get file name and line number 
		std::string tempstr = get_inst_loc( inst );

		std::vector<std::string> tempvec;
                boost::split(tempvec,  tempstr,  boost::is_any_of(":"), boost::token_compress_on);

		if (tempvec.size()>2)
			//llvm::dbgs() << "[doplog] filename:" << tempvec[0] <<  " line#:" << tempvec[1] << "\n";
			brloc_str = tempvec[0] + ":" + tempvec[1];
				
	}	

        nodeQueue.push( pvertex->nodeid );  //push the first (seed) node
	while ( !nodeQueue.empty() ) {
		std::string tempnodeid = nodeQueue.front(); //check the current node
		if(VisitedSet.insert(tempnodeid).second == false)
                {
                        //llvm::dbgs() << "[doplog] VisitedSet.insert duplicate:" <<tempnodeid<< "\n";
                        nodeQueue.pop(); //the first node in queue has been processed, just skip it.
                        continue;
              	}
		//retrieve tempnodeid's backward dd
		pvertex = ddGraph.findvertexbyid( tempnodeid );
		std::set<std::string>::iterator it;
		for(it=pvertex->incomingset.begin(); it!=pvertex->incomingset.end(); it++) {
	
			nodeQueue.push( *it );	 
			vertex* tempvertex = ddGraph.findvertexbyid( *it );
			if ( tempvertex != NULL ) {
				llvm::dbgs() << "[doplog]" << "backward tracing: " << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << "\n";
				forward_ddSet.insert(tempvertex->inst);
				//count if the backward inst is in the same line 
				if ( is_counting == true && tempvertex->loc.find( brloc_str ) != std::string::npos ) {
					count++;
				}
			}		
		}
		nodeQueue.pop();
	}
	//record the counting
	if ( is_counting == true && count >0 ) {
		llvm::dbgs() << "[doplog]" << "inst: " << inst  <<" ####br_inst_count:" <<  count << "\n";
	}
		
}
	return forward_ddSet;

    }

    void find_allforward_br( std::string root_inst, std::string current_br_inst ) {

	//llvm::dbgs() << "[doplog] in find_allforeward_dd, root_inst:" << root_inst << "\n";
	std::queue<std::string> nodeQueue;  //store nodeid
	std::set<std::string> VisitedSet;  //to avoid loop
	vertex* pvertex = ddGraph.findvertexbyinst( root_inst );
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] error, in find_allforeward_dd, can not find in ddGraph, root_inst:" << root_inst << "\n";
		return;			
        }
        nodeQueue.push( pvertex->nodeid );  //push the first (seed) node
	while ( !nodeQueue.empty() ) {
		std::string tempnodeid = nodeQueue.front(); //check the current node
		if(VisitedSet.insert(tempnodeid).second == false)
                {
                        //llvm::dbgs() << "[doplog] VisitedSet.insert duplicate:" <<tempnodeid<< "\n";
                        nodeQueue.pop(); //the first node in queue has been processed, just skip it.
                        continue;
                }
		//retrieve tempnodeid's backward dd
		pvertex = ddGraph.findvertexbyid( tempnodeid );
		std::set<std::string>::iterator it;
		for(it=pvertex->outgoingset.begin(); it!=pvertex->outgoingset.end(); it++) {
	
			nodeQueue.push( *it );	 
			vertex* tempvertex = ddGraph.findvertexbyid( *it );
			if ( tempvertex != NULL ) {
			
				if ( tempvertex->inst.find("br") != std::string::npos && countSubstring( tempvertex->inst, "label")>1 ) {
			        	
				       	if ( current_br_inst == "interprocedure" ){
						llvm::dbgs() << "[doplog]" << "find an #interprocedure# correlated br: " << tempvertex->inst <<" ###loc:" <<  tempvertex->loc << "\n";
						inter_correlated_br_list.insert(tempvertex->inst);
						
					} 	
					else if ( tempvertex->inst != current_br_inst ) {

						//llvm::dbgs() << "[doplog]" << "find a correlated br: " << tempvertex->inst <<" ###loc:" <<  tempvertex->loc << "\n";
						correlated_br_list.insert(tempvertex->inst);
					}
            			}
			}
		}
		nodeQueue.pop();
	}
	return;

    }

   void get_newfunc_br( std::string funcname, std::string argument ) {
	 
	std::string tempfuncname=funcname;
	if (funcname.find("@") != std::string::npos ) {
                tempfuncname = funcname.substr(1);
        }

        for(auto it = InsLocMap.cbegin(); it != InsLocMap.cend(); ++it) {
                 
                if ( it->first.find(argument+std::string(".addr") ) != std::string::npos && it->second.find( tempfuncname ) != std::string::npos ) {
                        llvm::dbgs() << "[doplog] in get_newfunc_br, find matched inst (new root): " << it->first << ", debugloc: " << it->second  <<  "\n";
                        //here find the br inst!!
			find_allforward_br( it->first, "interprocedure" );

			break;                       
                }
        }

	return;

    }

    void process_call_dd( std::string inst, MyGraph& ddGraphLocal ) {
	
	if ( inst.find( "call" ) == 0 && inst.find( ")" ) != std::string::npos && inst.find( "=" ) == std::string::npos ) { //inst should not contain "=", start with "call"

		llvm::dbgs() << "[doplog] in process_call_dd, inst: " << inst << '\n';
		
		std::string funcname;
		std::vector<std::string> paralist;
		extractfunc( inst, funcname, paralist );
		llvm::dbgs() << "[doplog] extracted funcname: " <<funcname << "\n";
		int index = 0;
		std::vector<int> ddparaindexlist;
        	for (std::vector<std::string>::const_iterator i = paralist.begin(); i != paralist.end(); ++i) {
                	if ( index%2 ==1 ) {
                        	llvm::dbgs() << "[doplog] function parameters: " << *i << ' ';   
				if ( (*i).find("%") == std::string::npos  ) {   
					llvm::dbgs() << "constant value ";
					continue;
				}

				std::string substr = *i;
				substr += " = ";
				std::string tempinst= ddGraphLocal.findinstbysubstr( substr );  
				if ( tempinst == "" ) {
					llvm::dbgs()  << "(not included:" << substr << "in ddGraphLocal)";
				} else {
					 
					std::string argument;
					if ( tempinst.find( "load" ) != std::string::npos ) { 
						llvm::dbgs() << "[doplog] load inst: " <<tempinst;
						//extract the argument_name from tempinst
						argument = extractloadargument( tempinst );
					} else {   
						argument = *i;
					}
					//add the index 
					argument += std::string("#")+ std::to_string(int(index/2));
					llvm::dbgs()  << "[" << argument  << "] ";
					ddparaindexlist.push_back(int(index/2)); 
					//we only need the index of an argument, match the corresponsing formal argument in FunctionList
				}		
                	}
                	index ++;
		}
		llvm::dbgs() << "\n";
		 
		if ( funcname.find( "%" ) != std::string::npos ) {			
		        std::vector<std::string> targetlist;
			getfuncptarget( funcname, targetlist );
			llvm::dbgs() << "[doplog] get function pointer "<< funcname << "'s targets ...\n";
			for (std::vector<std::string>::const_iterator i = targetlist.begin(); i != targetlist.end(); ++i) {
				llvm::dbgs() << "[doplog] target:" << *i << "\n";
				for(std::vector<int>::const_iterator it = ddparaindexlist.begin(); it != ddparaindexlist.end(); ++it) {
  					 
					std::string tempargument = getfuncformalargument(*i, *it);
					llvm::dbgs() << "[doplog] argument:" << tempargument << "\n";	
					 
					get_newfunc_br(*i, tempargument); 
 				}
				 
			}
			 
		} else if ( funcname.find( "@" ) != std::string::npos ) { //for non-function pointer, directly function name
			llvm::dbgs() << "[doplog] get function "<< funcname << "'s formal parameters ... \n";				
			for(std::vector<int>::const_iterator it = ddparaindexlist.begin(); it != ddparaindexlist.end(); ++it) {
                        	 
                                std::string tempargument = getfuncformalargument(funcname, *it);
                                llvm::dbgs() << "[doplog] argument:" << tempargument << "\n";
				get_newfunc_br(funcname, tempargument);
                                 
                	}
			if (ddparaindexlist.size()==0) {
				llvm::dbgs() << "[doplog] no dd paramenter, do not process this func-argument" << "\n";
			}
                         
		}
		 
	}
	return;
    }


    std::set<std::string> find_backwardload_cdcall( std::set<std::string> backward_ddSet ) { 
    	 
	std::set<std::string> backward_cdSet;
	for (auto root_inst : backward_ddSet) {
		 if ( root_inst.find("= load") != std::string::npos ) {
			llvm::dbgs() << "[doplog]" << "in  find_backwardload_cdcall, find a load inst: " << root_inst <<" ###loc:" << "\n";
			vertex* pvertex = cdGraph.findvertexbyinst( root_inst );  
			if ( pvertex == NULL ) {
				llvm::dbgs() << "[doplog] note, in find_backwardload_cdcall, can not find in cdGraph, root_inst:" << root_inst << "\n";
				return backward_cdSet;
			}
			//find if exist cd/functionall?
			std::set<std::string>::iterator it;
			for(it=pvertex->incomingset.begin(); it!=pvertex->incomingset.end(); it++) {
				vertex* tempvertex = ddGraph.findvertexbyid( *it );
				if ( tempvertex != NULL ) {
                        		int count = 0;
					size_t nPos = tempvertex->inst.find("call", 0);  
        		                while(nPos != std::string::npos) {
						count++;
						nPos = tempvertex->inst.find("call", nPos+1);
               		        	}
                       			if (count == 1) {
	 					llvm::dbgs() << "[doplog]" << "find a CALL inst: " << tempvertex->inst <<" ###loc:" <<  tempvertex->loc << "\n";
						backward_cdSet.insert(tempvertex->inst);
					}
				}
			}
		 }
	}
	return backward_cdSet;
    
    } //end of function def


    std::set<std::string> find_allforward_store( std::set<std::string> backward_ddSet , bool is_one_hop = false ) {
	
	std::set<std::string> forward_storeSet;
	MyGraph ddGraphLocal;

     for (auto root_inst : backward_ddSet) {

	ddGraphLocal.vmap.clear();

	std::queue<std::string> nodeQueue;  //store nodeid
	std::set<std::string> VisitedSet;  //to avoid loop
	
	vertex* pvertex = ddGraph.findvertexbyinst( root_inst );
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] error, in find_allforward_store, can not find in ddGraph, root_inst:" << root_inst << "\n";
		return forward_storeSet;			
        }
	 
        nodeQueue.push( pvertex->nodeid );  //push the first (seed) node
	while ( !nodeQueue.empty() ) {
		std::string tempnodeid = nodeQueue.front(); //check the current node
		
		if(VisitedSet.insert(tempnodeid).second == false)
                {
                         
                        nodeQueue.pop(); //the first node in queue has been processed, just skip it.
                        continue;
                }
		//retrieve tempnodeid's backward dd
		pvertex = ddGraph.findvertexbyid( tempnodeid );
		if ( pvertex == NULL ) {
			llvm::dbgs() << "[doplog] error, in find_allforward_store, can not find in ddGraph, root_inst:" << root_inst << "\n";
			return forward_storeSet;
		}
		//add the dd to ddGraphLocal.vmap
		if ( ddGraphLocal.vmap.insert(std::make_pair(pvertex->nodeid, pvertex)).second ) {
			 
		}

		std::set<std::string>::iterator it;
		for(it=pvertex->outgoingset.begin(); it!=pvertex->outgoingset.end(); it++) {
	
			if ( is_one_hop == false ) {
				nodeQueue.push( *it );
			}	 
			vertex* tempvertex = ddGraph.findvertexbyid( *it );
			if ( tempvertex != NULL ) {
				if ( tempvertex->inst.find("store") != std::string::npos ) {
					llvm::dbgs() << "[doplog]" << "find a store inst: " << tempvertex->inst <<" ###loc:" <<  tempvertex->loc << "\n";
					forward_storeSet.insert(tempvertex->inst);
					
            			}
			}
			 
#ifdef INTERPROCEDURE_ANALYSIS 
			int count = 0;
			size_t nPos = tempvertex->inst.find("call", 0); // fist occurrence
			while(nPos != std::string::npos) {
				count++;
				nPos = tempvertex->inst.find("call", nPos+1);
			}
			if (count == 1) {
				llvm::dbgs() << "[doplog]" << "find a CALL inst: " << tempvertex->inst <<" ###loc:" <<  tempvertex->loc << "\n";
				 	
				process_call_dd( tempvertex->inst, ddGraphLocal );
			} 
#endif				
			
		}
		nodeQueue.pop();
	}

       }

	return forward_storeSet;

    }


    void find_correlated_brinst( std::set<std::string> ddSet , std::string current_br_inst) {

	std::set<std::string>::iterator iter;

	for(iter=ddSet.begin(); iter!=ddSet.end();++iter) {
		 
		//consider the current *iter as a root, find all foreward/downstream dd, except current_brinst
		 find_allforward_br( *iter, current_br_inst );
		 //
	}	
    }

    void dump_branch_analysis_log(std::string branch1_loc, std::string branch2_loc, std::ofstream& logfile) {

	logfile << branch1_loc << " " <<  branch2_loc <<  "\n";
	 
    }

    void BB_Correlation_Analysis () {
	 
	std::string branch_analysis_log_file = "./branch_analysis_details.log";

        std::ofstream branch_analysis_log;
        branch_analysis_log.open( branch_analysis_log_file, std::ofstream::out | std::ofstream::trunc );
	//log setting end

	std::vector<std::string> brlist;
	std::string temp_inst;
	std::map<std::string, vertex*>::iterator it;
        for(it=cdGraph.vmap.begin(); it!=cdGraph.vmap.end(); ++it) {
	    temp_inst =  it->second->inst;

	    if ( temp_inst.find("br") != std::string::npos && countSubstring( temp_inst, "label")>1 ) {
               brlist.push_back( temp_inst  );
            }
     	}

	std::set<std::string> backward_ddSet;
	std::set<std::string> storeSet;
	std::set<std::string> storeinst_backward_ddSet;
	std::set<std::string> storeinst_backward_ddSet2;
	std::set<std::string> backward_cdSet;
	 
	std::ofstream outfile;
	outfile.open("./br_statistics_summary.log",  std::ofstream::out | std::ofstream::trunc);	
	
	llvm::dbgs() << "[doplog] in BB_Correlation_Analysis"<<"\n";

	int br_inst_count=0;
	for (std::vector<std::string>::const_iterator it = brlist.begin(); it != brlist.end(); ++it) {
		llvm::dbgs() << "[doplog] BR INST:" << *it <<  " ###loc:" << get_inst_loc( *it ) << "\n";
		backward_ddSet.clear();
		storeSet.clear();
		storeinst_backward_ddSet.clear();
		storeinst_backward_ddSet2.clear();
		backward_cdSet.clear();

		correlated_br_list.clear();
		inter_correlated_br_list.clear();
		br_inst_count = 0;
		storeSet.insert(*it);  //reuse the storeSet, we actually just need to find_allbackward_dd of *it. 
		backward_ddSet = find_allbackward_dd( storeSet , true, br_inst_count );  //true ==> counting the inst of each br

		 
		llvm::dbgs() << "[doplog] after find_allbackward_dd ==> find_backwardload_cdcall" << "\n";

		llvm::dbgs() << "[doplog] after find_backwardload_cdcall ==> find_allforward_store" << "\n";	
	 
		storeSet = find_allforward_store ( backward_ddSet );
		llvm::dbgs() << "[doplog] after find_allforward_store ==> find_allbackward_dd" << "\n";
		 
		storeinst_backward_ddSet = find_allbackward_dd( storeSet );
		
		backward_cdSet = find_backwardload_cdcall( storeinst_backward_ddSet );	
		storeSet.insert(backward_cdSet.begin(), backward_cdSet.end());
		
		storeinst_backward_ddSet2 = find_allbackward_dd( storeSet );

		
		storeinst_backward_ddSet.insert(storeinst_backward_ddSet2.begin(), storeinst_backward_ddSet2.end());

		llvm::dbgs() << "[doplog] after find_allbackward_dd ==> find_correlated_brinst" << "\n";
 
		find_correlated_brinst ( storeinst_backward_ddSet, *it ); 

		//print the results
		if ( correlated_br_list.size() >0 || inter_correlated_br_list.size()>0 ) {

			llvm::dbgs() << "[result] Result: br inst:" << *it <<  " ###loc:" << get_inst_loc( *it ) << "\n";
			for (auto &brinst: correlated_br_list) {
				llvm::dbgs() << "[result] intra-procedure correlated br inst:" << brinst <<  " ###loc:" << get_inst_loc( brinst ) << "\n";
				dump_branch_analysis_log( get_inst_loc( *it ), get_inst_loc( brinst ), branch_analysis_log );
			}
			for (auto &brinst: inter_correlated_br_list) {
				llvm::dbgs() << "[result] inter-procedure correlated br inst:" << brinst <<  " ###loc:" << get_inst_loc( brinst ) << "\n";
				dump_branch_analysis_log( get_inst_loc( *it ), get_inst_loc( brinst ), branch_analysis_log );
			}
		}
 
		if ( br_inst_count == 2) {  //simple branch
					
			backward_ddSet.clear();
	                storeSet.clear();
			storeSet.insert(*it);
			backward_ddSet = find_allbackward_dd( storeSet );
			storeSet = find_allforward_store( backward_ddSet, true ); //true means just find one-hop forward_store
			
			std::string store_str="" ;
			for(auto storeinst : storeSet) {
				
				//get localtion info also
				vertex* pvertex = ddGraph.findvertexbyinst( storeinst );	 
				if ( pvertex != NULL ) {
                			//llvm::dbgs() << "[doplog] error, in coarsegrained_analysis, can not find in ddGraph, inst:" << source_inst << "\n";
                			std::string tempstr = "#"+storeinst+"#"+ pvertex->loc;
					store_str += tempstr;
			        }
						  
			}
			outfile << correlated_br_list.size() << "\t" << br_inst_count << "\t" <<  *it <<  "#" << get_inst_loc( *it ) << "\t" << store_str << "\n";
			//outfile  ==> ./br_statistics_summary.log
		
		} else {
			 
			outfile << correlated_br_list.size() << "\t" << br_inst_count << "\t" <<  *it <<  "#" << get_inst_loc( *it ) << "\n";
		}

        }

	outfile.close();
	branch_analysis_log.close();

    }
 

    std::string extractloadargument( std::string inst ) {
	
	int start=0;
	start = inst.find("load");
	if ( start == std::string::npos ) {
		llvm::dbgs() << "[doplog] Error, in extractloadargument, no load, inst: "<< inst <<"\n";
		return "";
	}
	std::string tempstr = inst.substr( start );
 
	start=0;
        if ( tempstr.find( "@" ) != std::string::npos ) {
                start = tempstr.find("@");
        } else {
                start = tempstr.find("%");
        }
        if ( start == 0) {
                llvm::dbgs() << "[doplog] Error!!! in extractloadargument\n";
		return "";
        }
	int end = tempstr.find(","); 
	 
        return tempstr.substr(start, end-start);
    }

    void extractfunc( std::string inst, std::string &func, std::vector<std::string> &para ) {

	int funcstart=0;
	if ( inst.find( "@" ) != std::string::npos ) {
  		funcstart = inst.find("@");
	} else {
		funcstart = inst.find("%");
	}
	if ( funcstart == 0) {
		llvm::dbgs() << "[doplog] Error!!! in extractfunc\n";
	}
  	int funcend = inst.find("(",funcstart);  
	int endpos = inst.find(")",funcstart);

  	func = inst.substr(funcstart, funcend-funcstart);
  	std::string parastr = inst.substr(funcend+1, endpos-funcend-1);
        boost::split(para, parastr, boost::is_any_of(", "), boost::token_compress_on);
	return;
    }

    void getfuncptarget( std::string funcname, std::vector<std::string> &targetlist ) {

	std::string substr = funcname;
	substr += " = load";
	std::string inst=ddGraph.findinstbysubstrs( substr, "** %" );   
 
	if ( inst.find("** %") != std::string::npos ) {
	
		int pfuncstart = inst.find("** %");
	        int endpos = inst.find(",", pfuncstart);
		std::string pfuncstr = inst.substr ( pfuncstart, endpos-pfuncstart );

		std::map<std::string, vertex*>::iterator it;
		for(it=ddGraph.vmap.begin(); it!=ddGraph.vmap.end(); ++it) {
                	if ( it->second->inst.find("store") != std::string::npos && it->second->inst.find(pfuncstr) != std::string::npos && it->second->inst.find("@") != std::string::npos ) {
                        	
				int targetstart = it->second->inst.find("@");
		                int targetend = it->second->inst.find(",", targetstart);
				 
				targetlist.push_back( it->second->inst.substr (targetstart, targetend-targetstart)  );
                	}
                }
	}
	else {
		llvm::dbgs() << "[doplog] Error: in getfuncptarget, unknonw pattern, return! " << inst << "\n";
	}
    }

    std::string getfuncformalargument(std::string funcname, int index) {
	 
	std::string tempfuncname = funcname;
	if (funcname.find("@") != std::string::npos ) {
		tempfuncname = funcname.substr(1);
	}
	std::vector<FuncArg>::iterator it;
	for(it=FunctionList.begin(); it!=FunctionList.end(); ++it) {
        	if ( !it->funcname.compare(tempfuncname) ) {
			if ( index < it->arglist.size() ) {
				std::string tempstr = it->arglist[index];
				int start = tempstr.find("%");
				 
			        return tempstr.substr(start);				
			} else {
				llvm::dbgs() << "[doplog] Error, getfuncformalargument() !\n";
                		return "";
			}
                }
	}
	llvm::dbgs() << "[doplog] Error, in getfuncformalargument() no hit!\n";
        return "";
    }

    void newfunc_dd_analysis( std::string funcname, std::string argument ) {
	 
	std::string tempfuncname=funcname;
	if (funcname.find("@") != std::string::npos ) {
                tempfuncname = funcname.substr(1);
        }

        for(auto it = InsLocMap.cbegin(); it != InsLocMap.cend(); ++it) {
                
                if ( it->first.find(argument+std::string(".addr") ) != std::string::npos && it->second.find( tempfuncname ) != std::string::npos ) {
                        llvm::dbgs() << "[doplog] in newfunc_dd_analysis, find matched inst (new root): " << it->first << ", debugloc: " << it->second  <<  "\n";
    	 		if (is_coarsegrained_analysis == false) {
				detectability_analysis( it->first );    
			} else {
				coarsegrained_analysis( it->first );
			}
                        break;                       
                }
        }

	return;

    }


    void check_interprocedure_dd( std::string inst, MyGraph& ddGraphLocal ) {
	 
	int count = 0;
	size_t nPos = inst.find("call", 0); // fist occurrence
	while(nPos != std::string::npos) {
		count++;
		nPos = inst.find("call", nPos+1);
	}
	if (count > 1) {
		 
		return;
	} else if (count == 0) 
		return;

	if ( inst.find( "call" ) == 0 && inst.find( ")" ) != std::string::npos && inst.find( "=" ) == std::string::npos ) { //inst should not contain "=", start with "call"

		llvm::dbgs() << "[doplog] inst with call: " << inst << '\n';
		
		std::string funcname;
		std::vector<std::string> paralist;
		extractfunc( inst, funcname, paralist );
		llvm::dbgs() << "[doplog] funcname: " <<funcname << "\n";
		int index = 0;
		std::vector<int> ddparaindexlist;
        	for (std::vector<std::string>::const_iterator i = paralist.begin(); i != paralist.end(); ++i) {
                	if ( index%2 ==1  ) {
                        	llvm::dbgs() << "[doplog] function parameters: " << *i << ' ';  //implicit meaning: if a func call is dd, that's because only its parameter may dd
				 
				std::string substr = *i;
				substr += " = ";
				std::string tempinst= ddGraphLocal.findinstbysubstr( substr ); //if not dd, do not store it to ddparalist
				if ( tempinst == "" ) {
					llvm::dbgs()  << "(not included:" << substr << "in ddGraphLocal)";
				} else {
					 
					std::string argument;
					if ( tempinst.find( "load" ) != std::string::npos ) { 
						 
						argument = extractloadargument( tempinst );
					} else {  
						argument = *i;
					}
					 
					argument += std::string("#")+ std::to_string(int(index/2));
					llvm::dbgs()  << "[" << argument  << "] ";
					ddparaindexlist.push_back(int(index/2)); 
					 
				}		
                	}
                	index ++;
		}
		llvm::dbgs() << "\n";
		 
		if ( funcname.find( "%" ) != std::string::npos ) {			
		        std::vector<std::string> targetlist;
			getfuncptarget( funcname, targetlist );
			llvm::dbgs() << "[doplog] get function pointer "<< funcname << "'s targets ...\n";
			for (std::vector<std::string>::const_iterator i = targetlist.begin(); i != targetlist.end(); ++i) {
				llvm::dbgs() << "[doplog] target:" << *i << "\n";
				for(std::vector<int>::const_iterator it = ddparaindexlist.begin(); it != ddparaindexlist.end(); ++it) {
  					 
					std::string tempargument = getfuncformalargument(*i, *it);
					llvm::dbgs() << "[doplog] argument:" << tempargument << "\n";	
					 
					newfunc_dd_analysis(*i, tempargument); 
 				}
				 
			}
			 
		} else if ( funcname.find( "@" ) != std::string::npos ) { //for non-function pointer, directly function name
			llvm::dbgs() << "[doplog] get function "<< funcname << "'s formal parameters ... \n";				
			for(std::vector<int>::const_iterator it = ddparaindexlist.begin(); it != ddparaindexlist.end(); ++it) {
                        	 
                                std::string tempargument = getfuncformalargument(funcname, *it);
                                llvm::dbgs() << "[doplog] argument:" << tempargument << "\n";
				newfunc_dd_analysis(funcname, tempargument);
                                 
                	}
			if (ddparaindexlist.size()==0) {
				llvm::dbgs() << "[doplog] no dd paramenter, do not process this func-argument" << "\n";
			}
                         
		}
		 
	}
	return ;
    }

    bool disect_locinfo(std::string locinfo,  std::string &funcname, std::string &sourcefile, int &linenumber ) {
	//rootfunc

	llvm::dbgs() << "[doplog] in disect, locinfo: " << locinfo << "\n";

	std::vector<std::string> tempvec1;
	boost::split(tempvec1, locinfo, boost::is_any_of("#"), boost::token_compress_on);
	if (tempvec1.size()>2) {
		funcname = tempvec1[1];
       	}
	 
	if ( funcname == rootfunc  ) 
	{
		
		if (tempvec1[0].size()>3) {
               		std::vector<std::string> tempvec2;
               		boost::split(tempvec2, tempvec1[0], boost::is_any_of(":"), boost::token_compress_on);
			linenumber = std::stoi( tempvec2[1] );
			sourcefile = tempvec2[0]; 
			llvm::dbgs() << "[doplog] in disect, funcname==rootfunc line:" << linenumber << " sourcefile:" << sourcefile << "\n";
			return true;
        	}
	} else {
		 
		std::map<std::string, std::set<std::string> >::iterator p;
		

		p = callgraph.find(rootfunc);
		if(p != callgraph.end()) {
			 
			for (std::set<std::string>::iterator it1 = p->second.begin(); it1 != p->second.end(); ++it1) {
				 
				std::string tempstr=*it1;	
				if (tempstr.find( funcname ) != std::string::npos) {
					 
					llvm::dbgs() << "[doplog] find the callsite!!! " << tempstr  << "\n";
					boost::split(tempvec1, tempstr, boost::is_any_of("#"), boost::token_compress_on);
					if (tempvec1.size()>1) {
						std::vector<std::string> tempvec2;
                        			boost::split(tempvec2, tempvec1[1], boost::is_any_of(":"), boost::token_compress_on);
                        			linenumber = std::stoi( tempvec2[1] );
                        			sourcefile = tempvec2[0];									
						llvm::dbgs() << "[doplog] in disect, funcname!=rootfunc line:" << linenumber << " sourcefile:" << sourcefile << "\n";
						return true;
					} else {
						return false;
					}

				}
			}
		} else {
			return false;
		}
	}

	return false;
    }

    /////
    void initialize_detectability_analysis() {
	rootfunc = "main";
	is_analyzing_upstream=true;    
	downstream_dd=false;
	AttackPoint attackpoint;
    	attackpoint.funcname = "main";
    	attackpoint.line = 52;
    	attackpoint.variable = "flag";
	attackpoint.filename = "flagexample.c";   
         
	std::string dop_variable = "@flag";
	std::string extra_match =  "alloca";
	std::string source_inst = "";
	
	llvm::dbgs() << "[doplog] in func detectability_analysis" << "\n";	

	source_inst = "%flag = alloca i32, align 4 main";
	

	/*for(auto it = InsLocMap.cbegin(); it != InsLocMap.cend(); ++it)
    	{
		//if ( it->first.find(dop_variable) != std::string::npos && it->second.find(variable_loc) != std::string::npos ) {
		//&& it->first.find(extra_match) != std::string::npos
		if ( it->first.find(dop_variable) != std::string::npos && it->first.find(extra_match) != std::string::npos ) {
    			llvm::dbgs() << "[doplog] find matched inst: " << it->first << ", debugloc: " << it->second  <<  "\n";
			source_inst = it->first ;
			break;
			//break;
		}
    	}*/
	if (source_inst == "") {		
		llvm::dbgs() << "[doplog] error, source_inst void" << "\n";
		return;
	}
	//detectability_analysis( source_inst, attackpoint ); ////not distinguish the upstream and downstream areas
	find_updown_sources( source_inst, attackpoint );

	//after the analysis, print out results
	llvm::dbgs() << "[doplog] #######################　ddGraphUp size:" << ddGraphUp.vmap.size() << "\n";
	ddGraphUp.dumpallnodes();
	llvm::dbgs() << "[doplog] ####################### ddGraphDown size: " << ddGraphDown.vmap.size() <<  "\n";
	ddGraphDown.dumpallnodes();
	
    }
    
    void detectability_analysis( std::string source_inst, AttackPoint attackpoint=AttackPoint()) {   //not distinguish the upstream and downstream areas

	MyGraph ddGraphLocal;
	ddGraphLocal.vmap.clear(); / 	

	vertex* pvertex = ddGraph.findvertexbyinst( source_inst );	
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] Oops! can not find in ddGraph, inst:" << source_inst << "\n";
		return;
	} else {
		//llvm::dbgs() << "[doplog] Yes, find in ddGraph, inst:" << source_inst << "\n";
	}
		
	 
	std::queue<std::string> nodeQueue;  //store nodeid
       	nodeQueue.push( pvertex->nodeid );
	
	std::set<std::string> VisitedSet;  //to avoid loop 
       	VisitedSet.clear();
	while ( !nodeQueue.empty() ) {  //not sure whether exist loops, but just prevent loops by VisitedSet
        
        	std::string tempnodeid = nodeQueue.front();
       		//insert to the VisitedSet to avoid the loop
        	if(VisitedSet.insert(tempnodeid).second == false)
        	{
       			//llvm::dbgs() << "[doplog] VisitedSet.insert duplicate:" <<tempnodeid<< "\n";
			nodeQueue.pop(); //the first node in queue has been processed, just skip it.
        		continue;
       		} //avoid loop end
        	else {
        		//llvm::dbgs() << "[doplog] VisitedSet.insert nodeid:" <<tempnodeid<< "\n";	
        	}
                //retrieve tempnodeid's downstream dd
        	pvertex = ddGraph.findvertexbyid( tempnodeid );
        	if ( pvertex != NULL ) {			
			//add the dd to ddGraphLocal.vmap
			if ( ddGraphLocal.vmap.insert(std::make_pair(pvertex->nodeid, pvertex)).second ) { //add the root to ddGraphLocal
                		//llvm::dbgs() << "[doplog] added one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
       			} else {
                		llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
        		}
			//find all the forward dd from this node.
       			std::set<std::string>::iterator it;
			for(it=pvertex->outgoingset.begin(); it!=pvertex->outgoingset.end(); it++) {
				vertex* tempvertex = ddGraph.findvertexbyid( *it );
				 
				nodeQueue.push( *it );
				 
				bool pt_related_inst=false;
                                if ( tempvertex->inst.find( "call" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos ) { //inst should not contain "=", start with "call"
                                        pt_related_inst=true;
                                } else if ( tempvertex->inst.find( "br" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos  ) {
                                        pt_related_inst=true;
					global_dopbr_count ++;   
					llvm::dbgs() << "[doplog]" <<  tempnodeid << "'s forward dd:" << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << ", add to nodeQueue\n"; 
                                }
                                if ( pt_related_inst==true ) {

					if ( is_analyzing_upstream == true) {
                                        	if ( ddGraphUp.vmap.insert(std::make_pair(tempvertex->nodeid, tempvertex)).second ) {
                                                	llvm::dbgs() << "[doplog] added one entry to ddGraphUp, nodeid:" << tempvertex->nodeid << "\n";
	                                        } else {
        	                                        llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphUp, nodeid:" << tempvertex->nodeid << "\n";
                	                        }
					} else {
			                      	if ( ddGraphDown.vmap.insert(std::make_pair(tempvertex->nodeid, tempvertex)).second ) {
                                                        llvm::dbgs() << "[doplog] added one entry to ddGraphDown, nodeid:" << tempvertex->nodeid << "\n";
                                                } else {
                                                        llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphDown, nodeid:" << tempvertex->nodeid << "\n";
                                                }
					}
                                }

			}
        	}
        	nodeQueue.pop();

        }
	//begin check_interprocedure_dd for each inst in ddGraphLocal, inter-procedure analysis.
	
	std::map<std::string, vertex*>::iterator it;
       	for(it=ddGraphLocal.vmap.begin(); it!=ddGraphLocal.vmap.end(); ++it) {
		check_interprocedure_dd( it->second->inst, ddGraphLocal );
	} //temporarily commented out the inter-procedural analysis

    } //end

    
    void find_updown_sources (std::string source_inst, AttackPoint attackpoint) {  

	vertex* pvertex = ddGraph.findvertexbyinst( source_inst );	
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] error, can not find in ddGraph, inst:" << source_inst << "\n";
		return;
	}
	else {
		llvm::dbgs() << "[doplog] find root in ddGraph, inst:" << source_inst << " apoint:" << attackpoint.line << "\n";
	}
	 
	nodeQueueUp = std::queue<std::string>();
	nodeQueueDown = std::queue<std::string>();

	std::set<std::string>::iterator it;
	for(it=pvertex->outgoingset.begin(); it!=pvertex->outgoingset.end(); it++) {  
		vertex* tempvertex = ddGraph.findvertexbyid( *it );
		llvm::dbgs() << "[doplog]" <<  pvertex->nodeid << "'s forward dd:" << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << ", add to nodeQueue\n";
		 
		std::string funcname ="";
		std::string sourcefile="";
 		int linenumber=-1;
		 
		if ( disect_locinfo(tempvertex->loc, funcname, sourcefile, linenumber)==true ) {   
			if ( linenumber > attackpoint.line ) {
				downstream_dd = true;  
				llvm::dbgs() << "[doplog]" << " downstream roots, inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << "\n";
				nodeQueueDown.push( *it );
				bool pt_related_inst=false;
				 
				 if ( tempvertex->inst.find( "br" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos  ) {
					pt_related_inst=true;
				
				}
				if ( pt_related_inst==true ) {
					if ( ddGraphDown.vmap.insert(std::make_pair(tempvertex->nodeid, tempvertex)).second ) {
                                		llvm::dbgs() << "[doplog] added one entry to ddGraphDown, nodeid:" << tempvertex->nodeid << "\n";
                        		} else {
                                		llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphDown, nodeid:" << tempvertex->nodeid << "\n";
                        		}
				}	
			} else if ( linenumber <= attackpoint.line  ) {
				upstream_dd = true; 
				nodeQueueUp.push( *it );
                                llvm::dbgs() << "[doplog]" << " upstream roots, inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << "\n";
				bool pt_related_inst=false;
                                 
				if ( tempvertex->inst.find( "br" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos  ) {
                                        pt_related_inst=true;
                                }
                                if ( pt_related_inst==true ) {
                                        if ( ddGraphUp.vmap.insert(std::make_pair(tempvertex->nodeid, tempvertex)).second ) {
                                                llvm::dbgs() << "[doplog] added one entry to ddGraphUp, nodeid:" << tempvertex->nodeid << "\n";
                                        } else {
                                                llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphUp, nodeid:" << tempvertex->nodeid << "\n";
                                        }
                                }

			}
		}		
	}
	if ( downstream_dd ==true && upstream_dd == true ) {
		 
		is_analyzing_upstream = true;
		detectability_updownanalysis(source_inst,nodeQueueUp, 0);
		llvm::dbgs() << "[doplog] #########################################" << "\n"; 
		is_analyzing_upstream = false; 
		detectability_updownanalysis(source_inst,nodeQueueDown, 1);
	}
	 
	else if ( downstream_dd !=true && upstream_dd == true ) {
                //next process nodeQueueUP/Down respectively
                is_analyzing_upstream = true;
                detectability_updownanalysis(source_inst,nodeQueueUp, 0);
        }
	else if ( downstream_dd ==true && upstream_dd != true ) {
                //next process nodeQueueUP/Down respectively 
                is_analyzing_upstream = false;//used for choosing ddGraphUp or ddGraphDown
                detectability_updownanalysis(source_inst,nodeQueueDown, 1);
        }

    }//end
    
    void detectability_updownanalysis( std::string source_inst, std::queue<std::string> &nodeQueue, int updown ) {
	
	llvm::dbgs() << "[doplog] in detectability_updownanalysis" << "\n";
	
	MyGraph ddGraphLocal;
	ddGraphLocal.vmap.clear();  
	vertex* pvertex = ddGraph.findvertexbyinst( source_inst );
        if ( pvertex == NULL ) {
                llvm::dbgs() << "[doplog] error, can not find in ddGraph, inst:" << source_inst << "\n";
                return;
        }
	if ( ddGraphLocal.vmap.insert(std::make_pair(pvertex->nodeid, pvertex)).second ) {
        	//llvm::dbgs() << "[doplog] added one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
        }

	std::set<std::string> VisitedSet;  //to avoid loop 
       	VisitedSet.clear();
	while ( !nodeQueue.empty() ) {  //not sure whether exist loops, but just prevent loops by VisitedSet
        
        	std::string tempnodeid = nodeQueue.front();
       		//insert to the VisitedSet to avoid the loop
        	if(VisitedSet.insert(tempnodeid).second == false)
        	{
       			//llvm::dbgs() << "[doplog] VisitedSet.insert duplicate:" <<tempnodeid<< "\n";
			nodeQueue.pop(); //the first node in queue has been processed, just skip it.
        		continue;
       		} //avoid loop end
        	else {
        		//llvm::dbgs() << "[doplog] VisitedSet.insert nodeid:" <<tempnodeid<< "\n";	
        	}
                //retrieve tempnodeid's downstream dd
        	vertex* pvertex = ddGraph.findvertexbyid( tempnodeid );
        	if ( pvertex != NULL ) {			
			//add the dd to ddGraphLocal.vmap
			if ( ddGraphLocal.vmap.insert(std::make_pair(pvertex->nodeid, pvertex)).second ) { 
                		//llvm::dbgs() << "[doplog] added one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
       			} else {
                		llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
        		}
			//find all the forward dd from this node.
       			std::set<std::string>::iterator it;
			for(it=pvertex->outgoingset.begin(); it!=pvertex->outgoingset.end(); it++) {
				
				vertex* tempvertex = ddGraph.findvertexbyid( *it );
				llvm::dbgs() << "[doplog]" <<  tempnodeid << "'s forward dd:" << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << ", add to nodeQueue\n";
				nodeQueue.push( *it ); //either ddGraphUp or ddGraphDown	

				bool pt_related_inst=false;
                                 
				if ( tempvertex->inst.find( "br" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos  ) {
                                        pt_related_inst=true;	
                                }
                                if ( pt_related_inst==true ) {

					if ( is_analyzing_upstream == true) {
                                        	if ( ddGraphUp.vmap.insert(std::make_pair(tempvertex->nodeid, tempvertex)).second ) {
                                                	llvm::dbgs() << "[doplog] added one entry to ddGraphUp, nodeid:" << tempvertex->nodeid << "\n";
	                                        } else {
        	                                        llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphUp, nodeid:" << tempvertex->nodeid << "\n";
                	                        }
					} else {
			                      	if ( ddGraphDown.vmap.insert(std::make_pair(tempvertex->nodeid, tempvertex)).second ) {
                                                        llvm::dbgs() << "[doplog] added one entry to ddGraphDown, nodeid:" << tempvertex->nodeid << "\n";
                                                } else {
                                                        llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphDown, nodeid:" << tempvertex->nodeid << "\n";
                                                }
					}
                                }
				
			}
        	}
        	nodeQueue.pop();
        }
	//begin check_interprocedure_dd for each inst in ddGraphLocal, inter-procedure analysis.
	
	std::map<std::string, vertex*>::iterator it;
       	for(it=ddGraphLocal.vmap.begin(); it!=ddGraphLocal.vmap.end(); ++it) {
		check_interprocedure_dd( it->second->inst, ddGraphLocal );
	}

    } //end

     
    void dopgadget_analysis() {
	 
	dopgadgetfilename = "main.c";
	rootfunc = "main";  
	
	load_dopgedgets();
    }

    void load_dopgedgets () {
	//output log file 	
	std::string dopsrcpath = DOPSRCPATH;
	std::string coarsegrained_analysis_log_path = dopsrcpath + "coarse_analysis_" + dopgadgetfilename  + ".log";
	std::ofstream coarseanalysis_log;
	coarseanalysis_log.open(coarsegrained_analysis_log_path, std::ios_base::app);
	
	 
	std::string dopgadget_path= dopsrcpath+"dopgadgets_inst.log";
	std::ifstream in(dopgadget_path);
	if(!in) {
		llvm::dbgs() << "[doplog] Error, cannot open input file in load_dopgedgets" << "\n";
	    	return;
  	}

	std::string str;
	bool is_new_inst=false;
	DopGadget* tempDopGadget;
	std::vector<std::string> tempvec;

	while (std::getline(in, str)) {
	    	 
		//llvm::dbgs() << "[doplog] read line:    " << str  << "\n";
		if ( is_new_inst==false && str.find("gadgetinst") != std::string::npos) {
			
			tempDopGadget = new DopGadget();
		        tempvec.clear();
			boost::split(tempvec, str, boost::is_any_of(":"), boost::token_compress_on);
		        if (tempvec.size()>1) {
				tempDopGadget->gadget= tempvec[1];	
				is_new_inst=true;
				//llvm::dbgs() << "[doplog] find a new dop gadget:    " << tempDopGadget->gadget << "\n";
        		}
		} else if (is_new_inst==true && str.find("ptrinst") != std::string::npos) {
                        tempvec.clear();
                        boost::split(tempvec, str, boost::is_any_of(":"), boost::token_compress_on);
                        if (tempvec.size()>1) {
                                tempDopGadget->ptr= tempvec[1];
				//llvm::dbgs() << "[doplog] find a ptr:    " << tempDopGadget->ptr  << "\n";
                        }

		} else if (is_new_inst==true && str.find("function") != std::string::npos) {
                        tempvec.clear();
                        boost::split(tempvec, str, boost::is_any_of(":"), boost::token_compress_on);
                        if (tempvec.size()>1) {
                                tempDopGadget->function= tempvec[1];
                                //llvm::dbgs() << "[doplog] find a ptr:    " << tempDopGadget->ptr  << "\n";
                        }

                } else if (is_new_inst==true && str.find("location") != std::string::npos) {
                        tempvec.clear();
                        boost::split(tempvec, str, boost::is_any_of(":"), boost::token_compress_on);
                        if (tempvec.size()>1) {
                                tempDopGadget->location= tempvec[1];
                                //llvm::dbgs() << "[doplog] find a ptr:    " << tempDopGadget->ptr  << "\n";
                        }

                } else if (is_new_inst==true && str.find("valueinst") != std::string::npos) {
                        tempvec.clear();
                        boost::split(tempvec, str, boost::is_any_of(":"), boost::token_compress_on);
                        if (tempvec.size()>1) {
                                tempDopGadget->value= tempvec[1];
                        }
			DopGadgetArray.push_back(tempDopGadget);
			//detectability_analysis( tempDopGadget->ptr );
			is_new_inst=false;
                }
	}//while end

	//testing to print the DopGadgetArray
	for(std::vector<DopGadget*>::iterator it = DopGadgetArray.begin(); it != DopGadgetArray.end(); ++it) {
	
		llvm::dbgs() << "[doplog] Now analyze dopgedget ptr:    " << (*it)->ptr  << "\n";


		global_dopbr_count=0;

		//For the updown analysis
		
		is_analyzing_upstream=true;
	        downstream_dd=false;
        	AttackPoint attackpoint;
	        attackpoint.funcname = (*it)->function;
        	attackpoint.line = boost::lexical_cast<int>((*it)->location);
		ddGraphUp.vmap.clear();	
		ddGraphDown.vmap.clear();       
 
		coarsegrained_call_count=0;
		coarsegrained_br_count=0;
		is_coarsegrained_analysis=true;
		coarsegrained_brset.clear();
    		coarsegrained_callset.clear();

 
		vertex* pvertex = ddGraph.findvertexbyinst( (*it)->ptr+" "+(*it)->function );
	        if ( pvertex == NULL ) {
                	//here we backwardly get gadget's root in ddGraph ==> 
			std::string result =  backtraceroot ( (*it)->gadget+" "+(*it)->function);
			if (result == "") {
                		llvm::dbgs() << "[doplog] error, in load_dopgedgets, can not find in ddGraph, inst:" << (*it)->ptr << " skip this inst!!!\n";
				continue;	
			}
	        }
        	
		coarsegrained_analysis( (*it)->ptr+" "+(*it)->function );
		dump_coarsegrained_analysis_log( *it, coarseanalysis_log ); //every dop gadget generate one record!
 
	}
	coarseanalysis_log.close();
	
    }

    void dump_coarsegrained_analysis_log(DopGadget* gadget, std::ofstream& logfile) {
	//the dop gadget: #br #call
	logfile<<gadget->gadget<<"###"<<gadget->function<<"###"<<gadget->location<<"###"<< coarsegrained_br_count << "###" << coarsegrained_call_count <<  "\n";
	
	for(std::vector<std::string >::iterator it = coarsegrained_brset.begin(); it != coarsegrained_brset.end(); ++it) {
    		/* std::cout << *it; ... */
		logfile<< *it   <<  "\n";
	}

        for(std::vector<std::string >::iterator it = coarsegrained_callset.begin(); it != coarsegrained_callset.end(); ++it) {
                /* std::cout << *it; ... */
		logfile<< *it   <<  "\n";
        }

    }

 
    std::string backtraceroot ( std::string gadget_inst ) {

	vertex* pvertex = ddGraph.findvertexbyinst( gadget_inst );
	if ( pvertex == NULL ) {
		llvm::dbgs() << "[doplog] error, in backtraceroot, can not find in ddGraph, inst:" << gadget_inst << "\n";
		return "";			
           
        } else {
 
		std::set<std::string>::iterator it;
                for(it=pvertex->incomingset.begin(); it!=pvertex->incomingset.end(); it++) { 
			vertex* tempvertex = ddGraph.findvertexbyid( *it );
			llvm::dbgs() << "[doplog]" << "'backward tracing: " << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << "\n";
			if ( tempvertex != NULL ) {
				return  tempvertex->inst;
			}

		}
		return  "";
        }


    }
 
    void coarsegrained_analysis (std::string source_inst) {  
	//output in logfile 
	MyGraph ddGraphLocal;
        std::set<std::string> VisitedSet;  //to avoid loop 
        VisitedSet.clear();
        vertex* pvertex = ddGraph.findvertexbyinst( source_inst );
        if ( pvertex == NULL ) {
                llvm::dbgs() << "[doplog] error, in coarsegrained_analysis, can not find in ddGraph, inst:" << source_inst << "\n";
		exit(0);
                return;
        } else {
  		llvm::dbgs() << "[doplog] find the root: " <<  pvertex->nodeid << " inst:" << pvertex->inst <<" line:" <<  pvertex->loc << "\n";
	}

	std::queue<std::string> nodeQueue;  //store nodeid
        nodeQueue.push( pvertex->nodeid );

        while ( !nodeQueue.empty() ) {   

                std::string tempnodeid = nodeQueue.front();
                //insert to the VisitedSet to avoid the loop
                if(VisitedSet.insert(tempnodeid).second == false)
                {
                        //llvm::dbgs() << "[doplog] VisitedSet.insert duplicate:" <<tempnodeid<< "\n";
                        nodeQueue.pop(); //the first node in queue has been processed, just skip it.
                        continue;
                } //avoid loop end
                else {
                        //llvm::dbgs() << "[doplog] VisitedSet.insert nodeid:" <<tempnodeid<< "\n";    
                }
                //retrieve tempnodeid's downstream dd
                pvertex = ddGraph.findvertexbyid( tempnodeid );
                if ( pvertex != NULL ) {
			//add the dd to ddGraphLocal.vmap
                       	if ( ddGraphLocal.vmap.insert(std::make_pair(pvertex->nodeid, pvertex)).second ) { //add the root to ddGraphLocal
                        	//llvm::dbgs() << "[doplog] added one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
                       	} else {
                        	llvm::dbgs() << "[doplog] Error, failed adding one entry to ddGraphLocal, nodeid:" << pvertex->nodeid << "\n";
                       	}

			//find all the forward dd from this node.
                        std::set<std::string>::iterator it;
                        for(it=pvertex->outgoingset.begin(); it!=pvertex->outgoingset.end(); it++) {
                                vertex* tempvertex = ddGraph.findvertexbyid( *it );
                                llvm::dbgs() << "[doplog]" <<  tempnodeid << "'s forward dd:" << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << ", add to nodeQueue\n";
                                nodeQueue.push( *it );
                                if ( tempvertex->inst.find( "call" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos ) { //inst should not contain "=", start with "call"
                                        //log to file
					llvm::dbgs() << "[doplog]" <<  tempnodeid << "'s forward dd:" << *it  << " CALL inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << "\n";
					coarsegrained_call_count++;
					coarsegrained_callset.push_back(tempvertex->inst + " "+ tempvertex->loc );
	                       	} else if ( tempvertex->inst.find( "br" ) == 0 && tempvertex->inst.find( "=" ) == std::string::npos  ) {
                                        //log to file
                                        coarsegrained_br_count++;
					coarsegrained_brset.push_back( tempvertex->inst + " "+ tempvertex->loc );
                                        llvm::dbgs() << "[doplog]" <<  tempnodeid << "'s forward dd:" << *it  << " BR inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << "\n";
                                } 
                        }
                }
                nodeQueue.pop();
        }
         

        std::map<std::string, vertex*>::iterator it;
        for(it=ddGraphLocal.vmap.begin(); it!=ddGraphLocal.vmap.end(); ++it) {
                check_interprocedure_dd( it->second->inst, ddGraphLocal );
        } //temporarily commented out the inter-procedural analysis

	return;
    } //end of coarsegrained_analysis


   
   
    bool open(const char *new_file)
    {
        if (out.is_open()) {
            std::cerr << "File already opened (" << file << ")"
                      << std::endl;
            return false;
        } else
            reopen(new_file);


    }

    virtual std::ostream& printKey(std::ostream& os, KeyT key)
    {
        os << key;
        return os;
    }

    // \return - error state: true if there's an error, false otherwise
    virtual bool checkNode(std::ostream& os, NodeT *node)
    {
	    bool err = false;

	    if (!node->getBBlock()) {
	        err = true;
	        os << "\\nERR: no BB";
	    }

	    return err;
    }

    bool ensureFile(const char *fl)
    {
        if (fl)
            reopen(fl);

        if (!out.is_open()) {
            std::cerr << "File '" << file << "' not opened"
                      << std::endl;
            return false;
        }

        return true;
    }

    virtual bool dump(const char *new_file = nullptr,
                      const char *only_functions = nullptr)
    {
        (void) only_functions;

        if (!ensureFile(new_file))
            return false;

        start();

#ifdef ENABLE_CFG
        dumpBBs(dg);
#endif

        // even when we have printed nodes while
        // going through BBs, print nodes again,
        // so that we'll see if there are any nodes
        // that are not in BBs
        dump_nodes();
        dump_edges();

        // print subgraphs once we printed all the nodes
        if (!subgraphs.empty())
            out << "\n\t/* ----------- SUBGRAPHS ---------- */\n\n";
        for (auto sub : subgraphs) {
            dump_subgraph(sub);
        }


        end();

        out.close();
        return true;
    }

    /* if user want's manual printing, he/she can */

    void start()
    {
        out << "digraph \"DependenceGraph\" {\n";
        out << "\tcompound=true label=\"Graph " << dg
            << " has " << dg->size() << " nodes\\n\n"
            << "\tdd color: " << dd_color << "\n"
            << "\tcd color: " << cd_color << "\"\n\n";
    }

    void end()
    {
        out << "}\n";
    }

    void dumpSubgraphStart(DependenceGraph<NodeT> *sub,
                           const char *name = nullptr)
    {
    	llvm::dbgs() << "[doplog] in dumpSubgraphStart() in DG2Dot.h\n";

        out << "\t/* subgraph " << sub << " nodes */\n";
        out << "\tsubgraph cluster_" << sub << " {\n";
        out << "\t\tstyle=\"filled, rounded\" fillcolor=gray95\n";
        out << "\t\tlabel=\"Subgraph ";
        if (name)
            out << name << " ";

        out << "[" << sub << "]"
            << "\\nhas " << sub->size() << " nodes\n";

        uint64_t slice_id = sub->getSlice();
        if (slice_id != 0)
            out << "\\nslice: "<< slice_id;

        out << "\"\n";


        // dump BBs of the formal parameters
        dump_parameters(sub, 2);
    }

    void dumpSubgraphEnd(DependenceGraph<NodeT> *sub, bool with_nodes = true)
    {

    	llvm::dbgs() << "[doplog] in dumpSubgraphEnd() in DG2Dot.h\n";

        if (with_nodes) {
            // dump all nodes, to get it without BBlocks
            // (we may not have BBlocks or we just don't want
            // to print them

        	llvm::dbgs() << "[doplog] in dumpSubgraphEnd() in DG2Dot.h, with_nodes, dump subgraph:"<< sub <<"\n";

            for (auto I = sub->begin(), E = sub->end(); I != E; ++I) {


            	llvm::dbgs() << "[doplog] in dumpSubgraphEnd() in DG2Dot.h, will dump nodes: " << I->second <<"\n";

            
                dump_node(I->second, 2);
                dump_node_edges(I->second, 2);
            }

            if (dumpedGlobals.insert(sub->getGlobalNodes().get()).second) {
                for (auto& I : *sub->getGlobalNodes()) {

                	llvm::dbgs() << "[doplog] in dumpSubgraphEnd() in DG2Dot.h, GLOB will dump nodes: " << I.second <<"\n";

                    dump_node(I.second, 2, "GLOB");
                    dump_node_edges(I.second, 2);
                }
            }
        }

        out << "\t}\n";
    }

    void dumpSubgraph(DependenceGraph<NodeT> *sub)
    {

		llvm::dbgs() << "[doplog] in dumpSubgraph() in DG2Dot.h\n";
        dumpSubgraphStart(sub);
        dumpSubgraphEnd(sub);
    }

    void dumpBBlock(BBlock<NodeT> *BB, int ind = 2)
    {
    	llvm::dbgs() << "[doplog] in dumpBBlock(BBlock<NodeT> *BB, int ind = 2)\n";
        dumpBB(BB, ind);
    }

    void dumpBBlockEdges(BBlock<NodeT> *BB, int ind = 1)
    {
    	llvm::dbgs() << "[doplog] in dumpBBlockEdges(BBlock<NodeT> *BB, int ind = 1)\n";
        dumpBBedges(BB, ind);
    }

private:
    // what all to print?
    uint32_t options;

    void reopen(const char *new_file)
    {
        if (!new_file)
            new_file = "/dev/stdout";

        if (out.is_open())
            out.close();

        out.open(new_file);
        file = new_file;
    }

    void dumpBB(const BBlock<NodeT> *BB, int indent)
    {
        Indent Ind(indent);

        out << Ind << "/* Basic Block ";
        printKey(out, BB->getKey());
        out << " [" << BB << "] */\n";
        out << Ind << "subgraph cluster_bb_" << BB << " {\n";
        out << Ind << "\tstyle=filled fillcolor=white\n";
        out << Ind << "\tlabel=\"";

        printKey(out, BB->getKey());
        out << " [" << BB << "]";

        unsigned int dfsorder = BB->getDFSOrder();
        if (dfsorder != 0)
            out << Ind << "\\ndfs order: "<< dfsorder;

        uint64_t slice_id = BB->getSlice();
        if (slice_id != 0)
            out << "\\nslice: "<< slice_id;

        out << "\"\n";

        for (NodeT *n : BB->getNodes()) {
            // print nodes in BB, edges will be printed later
            out << Ind << "\tNODE" << n
                << " [label=\"" << n->getKey() << "\"]\n";
        }

        out << Ind << "} /* cluster_bb_" << BB << " */\n\n";
    }


    std::string  cl_convert2string(NodeT *node) {
	
	 
        std::string mystring;
	llvm::raw_string_ostream str_rso(mystring);
        node->getKey()->print(str_rso);
	return str_rso.str();

    }


 
    void cl_printBB(const BBlock<NodeT> *BB)
    {
     
        llvm::dbgs() << "Basic Block " << "\n"; 
        for (NodeT *n : BB->getNodes()) {
            // print nodes in BB, edges will be printed later
	    llvm::dbgs() << cl_convert2string(n)  << "\n";
        }


    }

    void dumpBBedges(BBlock<NodeT> *BB, int indent)
    {
        Indent Ind(indent);

        if (options & PRINT_CFG) {
            for (auto S : BB->successors()) {
                NodeT *lastNode = BB->getLastNode();
                NodeT *firstNode = S.target->getFirstNode();

                out << Ind
                    << "NODE" << lastNode << " -> "
                    <<   "NODE" << firstNode
                    << " [penwidth=5 color=red label=\"" << (int) S.label << "\""
                    << "  ltail=cluster_bb_" << BB
                    << "  lhead=cluster_bb_" << S.target << "]\n";

                 
                if ((int) S.label==0) {  //we only store the case of "True"
					std::string from_name, to_name;
					std::string from_loc="-1";
					std::string to_loc="-1";
					llvm::raw_string_ostream from_rso(from_name);
					llvm::raw_string_ostream to_rso(to_name);
					lastNode->getKey()->print(from_rso);
					from_name = from_rso.str();  //lookup the debug_loc info from InsLocMap
					firstNode->getKey()->print(to_rso);
					to_name = to_rso.str();  //lookup the debug_loc info from InsLocMap
					//llvm::dbgs() << "from instruction: "<< from_name << ", to instruction: "<< to_name << "\n";
					std::string trimed_from_name = trim(from_name);
					std::string trimed_to_name = trim(to_name);

					 
					trimed_from_name += " ";
					trimed_from_name += current_funcname;
					trimed_to_name += " ";
                                        trimed_to_name += current_funcname;

					auto from_itr = InsLocMap.find(trimed_from_name);
					auto to_itr = InsLocMap.find(trimed_to_name);
			                if(from_itr!=InsLocMap.end())
                			{
			                        from_loc=from_itr->second;
                			}
			                if(to_itr!=InsLocMap.end()) {
                        			to_loc=to_itr->second;
                			}

					//update cdGraph!!
					std::stringstream from_nodeid_buffer;
					from_nodeid_buffer << lastNode;
					std::stringstream to_nodeid_buffer;
					to_nodeid_buffer << firstNode;

					std::stringstream from_bbid_buffer;
					from_bbid_buffer << BB;

					std::stringstream to_bbid_buffer;
					to_bbid_buffer << S.target;
					
					llvm::dbgs() << "[CD Note] find a BB CF True, [nodeid:"<< from_nodeid_buffer.str() <<" inst:" << trimed_from_name << " loc:" << from_loc <<"]-->"<< "[nodeid:" << to_nodeid_buffer.str() << " inst" << trimed_to_name <<" loc:"<< to_loc << "] funcname:" << current_funcname << "\n";
					cfGraph.addedge(from_nodeid_buffer.str(), to_nodeid_buffer.str(), trimed_from_name, trimed_to_name, from_loc, to_loc, from_bbid_buffer.str(), from_bbid_buffer.str());
                }
  

            }
        }

        if (options & PRINT_REV_CFG) {
            for (auto S : BB->predecessors()) {
                NodeT *lastNode = S->getLastNode();
                NodeT *firstNode = BB->getFirstNode();

                out << Ind
                    << "NODE" << firstNode << " -> "
                    <<   "NODE" << lastNode
                    << " [penwidth=2 color=gray"
                    << "  ltail=cluster_bb_" << BB
                    << "  lhead=cluster_bb_" << S << " constraint=false]\n";
            }
        }

        if (options & PRINT_CD) {
            for (auto S : BB->controlDependence()) {
                NodeT *lastNode = BB->getLastNode();
                NodeT *firstNode = S->getFirstNode();

                out << Ind
                    << "NODE" << lastNode << " -> "
                    <<   "NODE" << firstNode
                    << " [penwidth=2 style=dotted color=blue"
                    << "  ltail=cluster_bb_" << BB
                    << "  lhead=cluster_bb_" << S << "]\n";

       
                std::string from_name, to_name;
                std::string from_loc="-1";
                std::string to_loc="-1";
                llvm::raw_string_ostream from_rso(from_name);
                llvm::raw_string_ostream to_rso(to_name);
                lastNode->getKey()->print(from_rso);
                from_name = from_rso.str();  //lookup the debug_loc info from InsLocMap
                firstNode->getKey()->print(to_rso);
                to_name = to_rso.str();  //lookup the debug_loc info from InsLocMap
                //llvm::dbgs() << "from instruction: "<< from_name << ", to instruction: "<< to_name << "\n";
                std::string trimed_from_name = trim(from_name);
                std::string trimed_to_name = trim(to_name);
		
		trimed_from_name += " ";
                trimed_from_name += current_funcname;
		trimed_to_name += " ";
                trimed_to_name += current_funcname;

                auto from_itr = InsLocMap.find(trimed_from_name);
                auto to_itr = InsLocMap.find(trimed_to_name);
                if(from_itr!=InsLocMap.end())
                {
                        from_loc=from_itr->second;
                }
                if(to_itr!=InsLocMap.end()) {
                        to_loc=to_itr->second;
                }

                //update cdGraph!!
                std::stringstream from_nodeid_buffer;
                from_nodeid_buffer << lastNode;
                std::stringstream to_nodeid_buffer;
                to_nodeid_buffer << firstNode;

                llvm::dbgs() << "[CD Note] find a BB CD, [nodeid:"<< from_nodeid_buffer.str() <<" inst:" << trimed_from_name << " loc:" << from_loc <<"]-->"<< "[nodeid:" << to_nodeid_buffer.str() << " inst" << trimed_to_name <<" loc:"<< to_loc << "] funcname:" << current_funcname << "\n";
                cdGraph.addedge(from_nodeid_buffer.str(), to_nodeid_buffer.str(), trimed_from_name, trimed_to_name, from_loc, to_loc);
       		 
		cl_printBB(S);
		 

            }

            for (BBlock<NodeT> *S : BB->getPostDomFrontiers()) {
                NodeT *start = BB->getFirstNode();
                NodeT *end = S->getLastNode();

                out << Ind
                    << "/* post-dominance frontiers */\n"
                    << "NODE" << start << " -> "
                    <<   "NODE" << end
                    << " [penwidth=3 color=green"
                    << "  ltail=cluster_bb_" << BB
                    << "  lhead=cluster_bb_" << S << " constraint=false]\n";
            }
        }

        if (options & PRINT_POSTDOM) {
            BBlock<NodeT> *ipd = BB->getIPostDom();
            if (ipd) {
                NodeT *firstNode = BB->getFirstNode();
                NodeT *lastNode = ipd->getLastNode();

                out << Ind
                    << "NODE" << lastNode << " -> "
                    <<   "NODE" << firstNode
                    << " [penwidth=3 color=purple"
                    << "  ltail=cluster_bb_" << BB
                    << "  lhead=cluster_bb_" << ipd << " constraint=false]\n";
            }
        }
    }

    void dump_parameters(NodeT *node, int ind)
    {
    	llvm::dbgs() << "[doplog] in dump_parameters(NodeT *node, int ind)\n";
        DGParameters<NodeT> *params = node->getParameters();

        if (params) {
            dump_parameters(params, ind, false);
        }
    }

    void dump_parameters(DependenceGraph<NodeT> *g, int ind)
    {

    	llvm::dbgs() << "[doplog] in dump_parameters(DependenceGraph<NodeT> *g, int ind)()\n";
        DGParameters<NodeT> *params = g->getParameters();

        if (params) {
            dump_parameters(params, ind, true);
        }
    }

    void dump_parameters(DGParameters<NodeT> *params, int ind, bool formal)
    {

    	llvm::dbgs() << "[doplog] in dump_parameters\n";

        Indent Ind(ind);

        // FIXME
        // out << Ind << "/* Input parameters */\n";
        // dumpBB(params->getBBIn(), data);
        // out << Ind << "/* Output parameters */\n";
        // dumpBB(params->getBBOut(), data);

        // dump all the nodes again to get the names
        for (auto it : *params) {
            DGParameter<NodeT>& p = it.second;
            if (p.in) {
                dump_node(p.in, ind, formal ? "[f] IN ARG" : "IN ARG");
                dump_node_edges(p.in, ind);
            } else
                out << "NO IN ARG";

            if (p.out) {
                dump_node(p.out, ind, formal ? "[f] OUT ARG" : "OUT ARG");
                dump_node_edges(p.out, ind);
            } else
                out << "NO OUT ARG";
        }

        for (auto I = params->global_begin(), E = params->global_end();
             I != E; ++I) {
            DGParameter<NodeT>& p = I->second;
            if (p.in) {
                dump_node(p.in, ind, formal ? "[f] GLOB IN" : "GLOB IN");
                dump_node_edges(p.in, ind);
            } else
                out << "NO GLOB IN ARG";

            if (p.out) {
                dump_node(p.out, ind, formal ? "[f] GLOB OUT" : "GLOB OUT");
                dump_node_edges(p.out, ind);
            } else
                out << "NO GLOB OUT ARG";
        }

        DGParameter<NodeT> *p = params->getVarArg();
        if (p) {
            if (p->in) {
                dump_node(p->in, ind, "[va] IN ARG");
                dump_node_edges(p->in, ind);
            } else
                out << "NO IN va ARG";

            if (p->out) {
                dump_node(p->out, ind, "[va] OUT ARG");
                dump_node_edges(p->out, ind);
            } else
                out << "NO OUT ARG";
        }
    }

    void dump_subgraph(DependenceGraph<NodeT> *sub)
    {
    	llvm::dbgs() << "[doplog] in dump_subgraph()\n";

        dumpSubgraphStart(sub);

#ifdef ENABLE_CFG
        // dump BBs in the subgraph
        dumpBBs(sub, 2);
#endif

        // dump all nodes again, if there is any that is
        // not in any BB
        for (auto I = sub->begin(), E = sub->end(); I != E; ++I)
            dump_node(I->second, 2);
        // dump edges between nodes
        for (auto I = sub->begin(), E = sub->end(); I != E; ++I)
            dump_node_edges(I->second, 2);

        dumpSubgraphEnd(sub);
    }

    void dumpBBs(DependenceGraph<NodeT> *graph, int ind = 1)
    {

    	llvm::dbgs() << "[doplog] in dumpBBs()\n";

        for (auto it : graph->getBlocks())
            dumpBB(it.second, ind);

        // print CFG edges between BBs
        if (options & (PRINT_CFG | PRINT_REV_CFG)) {
            out << Indent(ind) << "/* CFG edges */\n";
            for (auto it : graph->getBlocks())
                dumpBBedges(it.second, ind);
        }
    }

    void dump_node(NodeT *node, int ind = 1, const char *prefix = nullptr)
    {
        bool err = false;
        unsigned int dfsorder = node->getDFSOrder();
        unsigned int bfsorder = node->getDFSOrder();
        uint32_t slice_id = node->getSlice();
        Indent Ind(ind);

        out << Ind
            << "NODE" << node << " [label=\"";

        if (prefix)
            out << prefix << " ";

        printKey(out, node->getKey());

        if (node->hasSubgraphs())
            out << "\\nsubgraphs: " << node->subgraphsNum();
        if (dfsorder != 0)
            out << "\\ndfs order: "<< dfsorder;
        if (bfsorder != 0)
            out << "\\nbfs order: "<< bfsorder;

        if (slice_id != 0)
            out << "\\nslice: "<< slice_id;

    
        std::string str_inst , inst_loc;
        llvm::raw_string_ostream rso_inst(str_inst);
        node->getKey()->print(rso_inst);
        str_inst = rso_inst.str();
        std::string trim_str_inst = trim(str_inst);
 

        auto inst_itr = InsLocMap.find(trim_str_inst);

        if(inst_itr==InsLocMap.end())
        {
        	//llvm::dbgs() << "[DD Note] " << from_name << " or " << to_name << " do not exist in InsLocMap, skip\n";
        } else
        {
        	inst_loc=inst_itr->second;
        	//llvm::dbgs() << "get debugloc: "<< inst_loc << "\n";
        	//out << "\\n"<< str_inst;
        	out << "\\nLine#: "<< inst_loc << "\\nNodeId: "<< node;
        }
        
        // highlight it
        err = checkNode(out, node);

        // end of label
        out << "\" ";

        if (err) {
            out << "style=filled fillcolor=red";
        } else if (slice_id != 0)
            out << "style=filled fillcolor=greenyellow";
        else
            out << "style=filled fillcolor=white";

        out << "]\n";

        dump_parameters(node, ind);
        if (node->hasSubgraphs() && (options & PRINT_CALL)) {
            // add call-site to callee edges
            for (auto I = node->getSubgraphs().begin(),
                      E = node->getSubgraphs().end(); I != E; ++I) {
                out << Ind
                    << "NODE" << node
                    << " -> NODE" << (*I)->getEntry()
                    << " [label=\"call\""
                    << "  lhead=cluster_" << *I
                    << " penwidth=3 style=dashed]\n";
            }
        }
    }

    void dump_nodes()
    {
 

        out << "\t/* nodes */\n";
        for (auto I = dg->begin(), E = dg->end(); I != E; ++I) {
            auto node = I->second;

            dump_node(node);

            for (auto I = node->getSubgraphs().begin(),
                      E = node->getSubgraphs().end(); I != E; ++I) {
                subgraphs.insert(*I);
            }
        }

        if (dumpedGlobals.insert(dg->getGlobalNodes().get()).second)
            for (auto& I : *dg->getGlobalNodes())
                dump_node(I.second, 1, "GL");
    }

    void dump_edges()
    {
 

        for (auto I = dg->begin(), E = dg->end(); I != E; ++I)
            dump_node_edges(I->second);

        if (dumpedGlobals.insert(dg->getGlobalNodes().get()).second)
            for (auto& I : *dg->getGlobalNodes())
                dump_node_edges(I.second);
    }

    void dump_node_edges(NodeT *n, int ind = 1)
    {
 

        Indent Ind(ind);

        out << Ind << "/* -- node " << n->getKey() << "\n"
            << Ind << " * ------------------------------------------- */\n";


        if (options & PRINT_DD) {
            out << Ind << "/* DD edges */\n";
            for (auto II = n->data_begin(), EE = n->data_end(); II != EE; ++II) {
                out << Ind << "NODE" << n << " -> NODE" << *II
                    << " [color=\"" << dd_color << "\" rank=max]\n";

                llvm::dbgs() << "[DD Note], find a valid dd, "<< "NODE " << n << " -> NODE " << *II << "\n";
    		 
                std::string from_name, to_name;
                std::string from_loc="-999";
                std::string to_loc="-999";
                llvm::raw_string_ostream from_rso(from_name);
                llvm::raw_string_ostream to_rso(to_name);
                n->getKey()->print(from_rso);
                from_name = from_rso.str();  //lookup the debug_loc info from InsLocMap
                NodeT *temp = *II;
                temp->getKey()->print(to_rso);
                to_name = to_rso.str();  //lookup the debug_loc info from InsLocMap
                std::string trimed_from_name = trim(from_name);
		std::string trimed_to_name = trim(to_name);
                // llvm::dbgs() << "from instruction: "<< from_name << ", to instruction: "<< to_name << "\n";
		trimed_from_name += " ";
                trimed_from_name += current_funcname;
                trimed_to_name += " ";
                trimed_to_name += current_funcname;

   		auto from_itr = InsLocMap.find(trimed_from_name);
    		auto to_itr = InsLocMap.find(trimed_to_name);
    		if(from_itr!=InsLocMap.end())
    		{
    			from_loc=from_itr->second;
    		} 
		if(to_itr!=InsLocMap.end()) {
    			to_loc=to_itr->second;
    		}
		//update ddGraph!! will skip some over-long inst
		if ( trimed_from_name.size() < 150 && trimed_to_name.size() < 150 ) {

	    		std::stringstream from_nodeid_buffer;
	    		from_nodeid_buffer << n;
    			std::stringstream to_nodeid_buffer;
    			to_nodeid_buffer << *II;
	    		//llvm::dbgs() << "[DD Note] find a DD, ["<< trimed_from_name <<" "<< from_loc <<"]-->"<< "[" << trimed_to_name <<" "<< to_loc << "]\n";
    			llvm::dbgs() << "[DD Note] find a DD, ["<< from_nodeid_buffer.str() <<" " << trimed_from_name << " " << from_loc <<"]-->"<< "[" << to_nodeid_buffer.str() << " " << trimed_to_name <<" "<< to_loc << "] funcname:" << current_funcname <<  "\n";
	    		ddGraph.addedge(from_nodeid_buffer.str(), to_nodeid_buffer.str(), trimed_from_name, trimed_to_name, from_loc, to_loc);
		}
    		 
    	    }
        }

        if (options & PRINT_REV_DD) {
            out << Ind << "/* reverse DD edges */\n";
            for (auto II = n->rev_data_begin(), EE = n->rev_data_end();
                 II != EE; ++II)
                out << Ind << "NODE" << n << " -> NODE" << *II
                    << " [color=\"" << dd_color << "\" style=\"dashed\"  constraint=false]\n";
        }

        if (options & PRINT_CD) {
            out << Ind << "/* CD edges */\n";
            for (auto II = n->control_begin(), EE = n->control_end(); II != EE; ++II) {
                out << Ind << "NODE" << n << " -> NODE" << *II
                    << " [color=\"" << cd_color << "\"]\n";

                llvm::dbgs() << "[CD Note]  "<< "NODE" << n << " -> NODE" << *II << "\n";

            	 
                std::string from_name, to_name;
                std::string from_loc="-999";
                std::string to_loc="-999";
                llvm::raw_string_ostream from_rso(from_name);
                llvm::raw_string_ostream to_rso(to_name);
                n->getKey()->print(from_rso);
                from_name = from_rso.str();  //lookup the debug_loc info from InsLocMap
                NodeT *temp = *II;
                temp->getKey()->print(to_rso);
                to_name = to_rso.str();  //lookup the debug_loc info from InsLocMap
                //llvm::dbgs() << "from instruction: "<< from_name << ", to instruction: "<< to_name << "\n";
                std::string trimed_from_name = trim(from_name);
                std::string trimed_to_name = trim(to_name);
		trimed_from_name += " ";
                trimed_from_name += current_funcname;
                trimed_to_name += " ";
                trimed_to_name += current_funcname;

            	auto from_itr = InsLocMap.find(trimed_from_name);
            	auto to_itr = InsLocMap.find(trimed_to_name);
            	if(from_itr!=InsLocMap.end()) {
			from_loc=from_itr->second;
            	} 
		if(to_itr!=InsLocMap.end())  {
            		to_loc=to_itr->second;
		}
            	//update cdGraph!!
		if ( trimed_from_name.size() < 150 && trimed_to_name.size() < 150 ) {
			std::stringstream from_nodeid_buffer;
	            	from_nodeid_buffer << n;
        	   	std::stringstream to_nodeid_buffer;
            		to_nodeid_buffer << *II;
			
            		llvm::dbgs() << "[CD Note] find a CD, ["<< from_nodeid_buffer.str() <<" " << trimed_from_name << " " << from_loc <<"]-->"<< "[" << to_nodeid_buffer.str() << " " << trimed_to_name <<" "<< to_loc << "] funcname:" << current_funcname << "\n";
            		cdGraph.addedge(from_nodeid_buffer.str(), to_nodeid_buffer.str(), trimed_from_name, trimed_to_name, from_loc, to_loc);
		}
                
           }
        }

        if (options & PRINT_REV_CD) {
            out << Ind << "/* reverse CD edges */\n";
            for (auto II = n->rev_control_begin(), EE = n->rev_control_end();
                 II != EE; ++II)
                out << Ind << "NODE" << n << " -> NODE" << *II
                    << " [color=\"" << cd_color << "\" style=\"dashed\" constraint=false]\n";
        }
    }

    const char *dd_color = "black";
    const char *cd_color = "blue";

    DependenceGraph<NodeT> *dg;
    const char *file;
    std::set<DependenceGraph<NodeT> *> subgraphs;

protected:
    std::ofstream out;
};

} // debug
} // namespace dg

#endif // DG_2_DOT_H_

	//find all br instbrcdGraph
