#include <iostream>
#include <ostream>
#include <sstream>
#include <string>

#include "DG2Dot.h"
#include "llvm/LLVMNode.h"
#include <boost/algorithm/string.hpp>
#include <queue>

//#include "../dop_define.h"

#define EventFile "/home/cl/ControlFlowIntegrity/Events/EventList.txt"
#define ActionFile "/home/cl/ControlFlowIntegrity/Events/EventTriggerList.txt"
#define EventActionFile "/home/cl/ControlFlowIntegrity/Events/EventActionList.txt"

extern std::string current_funcname;
extern MyGraph cdGraph;
extern MyGraph ddGraph;
extern MyGraph cfGraph;
using namespace dg;
namespace dg {
namespace debug {

 
std::vector<MyBBDependency> MyBrkList;
std::vector<MyBBDependency> MyBBDependencyList;
std::vector<EventAction> MyEventActionList;
std::map<std::string, std::string> MyBBTable;
std::map<int, std::string> EventList;
std::map<int, std::string> ActionList;
std::ofstream outfile;

bool LoadEventFile(std::map<int, std::string>& EventList, std::map<int, std::string>& ActionList)
{
	outfile.open(EventActionFile,  std::ofstream::out | std::ofstream::trunc);
	std::ifstream infile(EventFile);  //you need to change the file path later!!!
	std::ifstream infile2(ActionFile);  //you need to change the file path later!!!
    if (!infile || !infile2) {
    	llvm::dbgs() << "could not open the file\n";
    	return false;
    }
	int index;
	std::string str;
	EventList.clear();
	ActionList.clear();
	llvm::dbgs() << "[Call] LoadEventList "<<"\n";
	while (infile >> index >> str)
	{
    	// process pair (a,b)
    	llvm::dbgs() << "Read EventList: " <<index << " " << str<< "\n";
    	EventList.insert(std::map<int, std::string>::value_type(index, str));
	}
	while (infile2 >> index >> str)
	{
    	// process pair (a,b)
    	llvm::dbgs() << "Read ActionList: " <<index << " " << str<< "\n";
    	ActionList.insert(std::map<int, std::string>::value_type(index, str));
	}
    return true;
}

// returns count of non-overlapping occurrences of 'sub' in 'str'
/*int countSubstring(const std::string& str, const std::string& sub)
{
    if (sub.length() == 0) return 0;
    int count = 0;
    for (size_t offset = str.find(sub); offset != std::string::npos;
	 offset = str.find(sub, offset + sub.length()))
    {
        ++count;
    }
    return count;
}*/



int isContainEvent(std::string str) {
	//return the index of the matched key
	llvm::dbgs() << "in isContainEvent, EventList size : " <<EventList.size() << "\n";
	std::map<int, std::string>::iterator itr;
    for(itr=EventList.begin();itr!=EventList.end();++itr) {
    	//llvm::dbgs() << "in isContainEvent check: " <<itr->second << "\n";
		if (str.find(itr->second) != std::string::npos) {

			llvm::dbgs() << "isContainEvent hit\n";
    		return itr->first;
		}
	}
	return -1;

}

int isContainAction(std::string str) {
	llvm::dbgs() << "in isContainAction, ActionList size : " <<ActionList.size() << "\n";
	std::map<int, std::string>::iterator itr;
    for(itr=ActionList.begin();itr!=ActionList.end();++itr) {
    	//llvm::dbgs() << "in isContainAction check: " <<itr->second << "\n";
		if (str.find(itr->second) != std::string::npos) {
			llvm::dbgs() << "isContainAction hit\n";
    		return itr->first;
		}
	}
	return -1;
}
 


/*
static std::ostream& operator<<(std::ostream& os, const analysis::Offset& off)
{
    if (off.offset == UNKNOWN_OFFSET)
        os << "UNKNOWN";
    else
        os << off.offset;

    return os;
}
*/

static std::ostream& printLLVMVal(std::ostream& os, const llvm::Value *val)
{
    if (!val) {
        os << "(null)";
        return os;
    }

    std::ostringstream ostr;
    llvm::raw_os_ostream ro(ostr);

    if (llvm::isa<llvm::Function>(val)) {
        ro << "FUNC " << val->getName().data();
    } else if (llvm::isa<llvm::BasicBlock>(val)) {
        ro << "label " << val->getName().data();
    } else {
        ro << *val;
    }

    ro.flush();

    // break the string if it is too long
    std::string str = ostr.str();
    if (str.length() > 100) {
        str.resize(40);
    }

    // escape the "
    size_t pos = 0;
    while ((pos = str.find('"', pos)) != std::string::npos) {
        str.replace(pos, 1, "\\\"");
        // we replaced one char with two, so we must shift after the new "
        pos += 2;
    }

    os << str;

    return os;
}

class LLVMDG2Dot : public debug::DG2Dot<LLVMNode>
{
public:


    // FIXME: make dg const
    LLVMDG2Dot(LLVMDependenceGraph *dg,
               uint32_t opts = debug::PRINT_CFG | debug::PRINT_DD | debug::PRINT_CD,
               const char *file = NULL)
        : debug::DG2Dot<LLVMNode>(dg, opts, file) {
		 
		if (LoadEventFile(EventList, ActionList)==false) {
			llvm::dbgs() << "[Error] LoadEventList return false "<<"\n";
		}
		 
    }

    /* virtual */
    std::ostream& printKey(std::ostream& os, llvm::Value *val)
    {
        return printLLVMVal(os, val);
    }

    /* virtual */
    bool checkNode(std::ostream& os, LLVMNode *node)
    {
        bool err = false;
        const llvm::Value *val = node->getKey();

        if (!val) {
            os << "\\nERR: no value in node";
            return true;
        }

        if (!node->getBBlock()
            && !llvm::isa<llvm::Function>(val)
            && !llvm::isa<llvm::GlobalVariable>(val)) {
            err = true;
            os << "\\nERR: no BB";
        }

        //Print Location in source file. Print it only for LLVM 3.6 and higher.
        // The versions before 3.6 had different API, so this is quite
        // a workaround, not a real fix. If anybody needs this functionality
        // on those versions, fix this :)
        if (const llvm::Instruction *I = llvm::dyn_cast<llvm::Instruction>(val)) {
            const llvm::DebugLoc& Loc = I->getDebugLoc();
#if ((LLVM_VERSION_MAJOR > 3)\
      || ((LLVM_VERSION_MAJOR == 3) && (LLVM_VERSION_MINOR > 6)))
            if(Loc) {
                os << "\" labelURL=\"";
                llvm::raw_os_ostream ross(os);
                Loc.print(ross);
#else
            if(Loc.getLine() > 0) {
                os << "\" labelURL=\"";
                llvm::raw_os_ostream ross(os);
                Loc.print(I->getParent()->getContext(), ross);
#endif
                ross.flush();
            }
        }

        return err;
        }

    bool dump(const char *new_file = nullptr,
              const char *dump_func_only = nullptr)
    {
        // make sure we have the file opened
        if (!ensureFile(new_file))
            return false;

        const std::map<llvm::Value *,
                       LLVMDependenceGraph *>& CF = getConstructedFunctions();

        llvm::dbgs() << "[doplog] in LLVMDG2Dot::dump() in LLVMG2Dot.h \n";

        start();

        for (auto& F : CF) {
            if (dump_func_only && !F.first->getName().equals(dump_func_only))
                continue;

            dumpSubgraph(F.second, F.first->getName().data());
        }

        end();

        return true;
    }



private:

    void dumpSubgraph(LLVMDependenceGraph *graph, const char *name)
    {

	current_funcname = name;
    	llvm::dbgs() << "[doplog] in dumpSubgraph() in LLVMG2Dot.h\n";
    	dumpSubgraphStart(graph, name);

        for (auto& B : graph->getBlocks()) {
            dumpBBlock(B.second);
        }

        for (auto& B : graph->getBlocks()) {
            dumpBBlockEdges(B.second);
        }

        dumpSubgraphEnd(graph);
    }
};

class LLVMDGDumpBlocks : public debug::DG2Dot<LLVMNode>
{
public:
    std::ofstream bbdependencyfile;  

     
	void BackwardSearchBBDependency(EventAction& ea, std::string blkid) {   //[Notice] used as a recursive function!!!
		//std::string currentblkid = blkid;
		bool isduplicateevent=false;

		//while (true) {
			//isfindevent=false;
			for(int i = 0; i < MyBBDependencyList.size(); i++)
			{
				if ( MyBBDependencyList[i].tobbid == blkid ) {
					//if MyBBDependencyList[i].brkbbid's instruction list contains any event, then do the following
					std::map<std::string, std::string>::iterator itr = MyBBTable.find(MyBBDependencyList[i].brkbbid);   //get the instruction list
					if ( itr != MyBBTable.end() )
					{
						std::string InstList=itr->second;
						replace(InstList.begin(), InstList.end(), '\n', '#');
						int eventIndex=isContainEvent(InstList);
						if (eventIndex>=0) {

							isduplicateevent=false;
							//if exist in ea.eventlist ==> break;  skip this blk
							for (int k = 0; k <ea.eventlist.size(); k++ ){
								if ( ea.eventlist[k].efunc == EventList[eventIndex]) {

									llvm::dbgs() << "BackwardSearchBBDependency, find a duplicate event: " << EventList[eventIndex] << "\n";
									isduplicateevent=true;
									break;
								}
							}
							if (isduplicateevent==true)
								break;
							//add to ea, and update the currentblkid
							Event tempEvent;
   							tempEvent.efunc = EventList[eventIndex];
    						tempEvent.efuncId = eventIndex;
    						if (MyBBDependencyList[i].label==1)
    							tempEvent.flag = false;
    						else
    							tempEvent.flag = true;
    						ea.eventlist.push_back(tempEvent);
							//currentblkid = MyBBDependencyList[i].brkbbid;
							//isfindevent= true;
							llvm::dbgs() << "BackwardSearchBBDependency, find one upstream blk with event: " << EventList[eventIndex] << " condition:" <<tempEvent.flag<< "\n";
							//break;  //here should not break out of the loop, since maybe multiple upstream blks
							BackwardSearchBBDependency(ea, MyBBDependencyList[i].brkbbid);   //here is a bug, exist duplicate
						}
					}
				}
			}
			return;
		//	if (isfindevent==false)
		//		return;  //if no hit, return
		//}
	}

    void MyAnalysis () {   //MyBrkList is used to generate the MyBBDependencyList!!
    	llvm::dbgs() << "[doplog] in MyAnalysis in LLVMG2Dot.h \n";

        for(int t=0;t<MyBBDependencyList.size();++t) {

        	llvm::dbgs() << "MyBrkList" << "　brkbbid:" << MyBBDependencyList[t].brkbbid << " -> tobbid:" << MyBBDependencyList[t].tobbid << "　brkinst:" << MyBBDependencyList[t].brkinst << " brkloc:" << MyBBDependencyList[t].brkloc << " label:"<< MyBBDependencyList[t].label << "\n";
			//now check Data denpencey of the brk inst, from ddGraph
        	//now we only consider True case in a brk
        	if  ( MyBBDependencyList[t].label == 0 ) {   //it means that the current brk (if true) triggers some bb (event-action pair)
        		vertex* pvertex = ddGraph.findvertexbyinst( trim(MyBBDependencyList[t].brkinst) );
        		if ( pvertex != NULL ) {

        			std::set<std::string> VisitedSet;
        			VisitedSet.clear();

        			llvm::dbgs() << "[doplog] find a match in ddGraph, nodeid of the inst:" << pvertex->nodeid << "\n";
        			MyBBDependencyList[t].brknodeid =  pvertex->nodeid;  //now get the nodeid
        			//find all the dd backwardly??
        			std::queue<std::string> nodeQueue;
        			nodeQueue.push( pvertex->nodeid );

        			while ( !nodeQueue.empty() ) {  //here is a bug, may exist loops, due to for/while loop
        				//push all backward dd nodeid to the queue, incomingset
        				std::string tempnodeid = nodeQueue.front();
        				//insert to the VisitedSet to avoid the loop
        				if(VisitedSet.insert(tempnodeid).second == false)
        				{

        					llvm::dbgs() << "[doplog] VisitedSet.insert duplicate:" <<tempnodeid<< "\n";
        					nodeQueue.pop();
        					continue;
        				} //avoid loop end
        				else {

        					llvm::dbgs() << "[doplog] VisitedSet.insert nodeid:" <<tempnodeid<< "\n";
        				}

        				pvertex = ddGraph.findvertexbyid( tempnodeid );
        				if ( pvertex != NULL ) {
        					std::set<std::string>::iterator it;
							for(it=pvertex->incomingset.begin(); it!=pvertex->incomingset.end(); it++) {
								vertex* tempvertex = ddGraph.findvertexbyid( *it );
								llvm::dbgs() << "[doplog]" <<  tempnodeid << "'s predecessor:" << *it  << " inst:" << tempvertex->inst <<" line:" <<  tempvertex->loc << ", push to the nodeQueue\n";
								nodeQueue.push( *it );

								MyBBDependencyList[t].DDlist.push_back(tempvertex);
							}
        				}
        				nodeQueue.pop();

        			}
        		}
        	}
        }
        //here can store in fil?
        //bbdependencyfile << blk <<"\t";

        //given sensor input, we can find the br inst, and it's triggering BB (ie,  MyBBDependencyList[t].tobb), all backward DD inst in DDlist

        //dump the event-action pairs
        for(int t=0;t<MyEventActionList.size();++t) {
			std::string str="";
			str = MyEventActionList[t].afunc+"#"+std::to_string(MyEventActionList[t].afuncId)+" ";
			for (int k=0;k<MyEventActionList[t].eventlist.size();k++) {
				str=str+MyEventActionList[t].eventlist[k].efunc+"#"+std::to_string(MyEventActionList[t].eventlist[k].efuncId)+"#"+std::to_string(MyEventActionList[t].eventlist[k].flag)+" ";
			}
			outfile << str <<"\n";
        }
    }

    LLVMDGDumpBlocks(LLVMDependenceGraph *dg,
                  uint32_t opts = debug::PRINT_CFG | debug::PRINT_DD | debug::PRINT_CD,
                  const char *file = NULL)
        : debug::DG2Dot<LLVMNode>(dg, opts, file) {

    	bbdependencyfile.open("/home/cl/ControlFlowIntegrity/bb_dependency.dat");   
    }

    /* virtual
    std::ostream& printKey(std::ostream& os, llvm::Value *val)
    {
        return printLLVMVal(os, val);
    }
    */

    /* virtual */
    bool checkNode(std::ostream&, LLVMNode *)
    {
        return false; // no error
    }

    bool dump(const char *new_file = nullptr,
              const char *dump_func_only = nullptr)
    {
        // make sure we have the file opened
        if (!ensureFile(new_file))
            return false;

        const std::map<llvm::Value *,
                       LLVMDependenceGraph *>& CF = getConstructedFunctions();

        llvm::dbgs() << "[doplog] in LLVMDGDumpBlocks::dump() in LLVMG2Dot.h \n";

        start();

        for (auto& F : CF) {
            // XXX: this is inefficient, we can get the dump_func_only function
            // from the module (F.getParent()->getModule()->getFunction(...)
            if (dump_func_only && !F.first->getName().equals(dump_func_only))
                continue;

            dumpSubgraph(F.second, F.first->getName().data());
        }

        end();

        bbdependencyfile.close();
        return true;
    }

private:

    void dumpSubgraph(LLVMDependenceGraph *graph, const char *name)
    {

	current_funcname= name;

    	llvm::dbgs() << "[doplog] in private dumpSubgraph(LLVMDependenceGraph *graph, const char *name) in LLVMG2Dot.h\n";
    	dumpSubgraphStart(graph, name);

    	//MyBrkList.clear();
        for (auto& B : graph->getBlocks()) {


        	llvm::dbgs() << "[doplog] in private dumpSubgraph(LLVMDependenceGraph *graph, const char *name) in LLVMG2Dot.h, will dumpBlock\n";

            dumpBlock(B.second);

        }

        for (auto& B : graph->getBlocks()) {

        	llvm::dbgs() << "[doplog] in private dumpSubgraph(LLVMDependenceGraph *graph, const char *name) in LLVMG2Dot.h, will dumpBlockEdges\n";

            dumpBlockEdges(B.second);
        }

        dumpSubgraphEnd(graph, false);
    }

    void dumpBlock(LLVMBBlock *blk)
    {
        out << "NODE" << blk << " [label=\"" ;

        std::ostringstream ostr;
        llvm::raw_os_ostream ro(ostr);

        ro << *blk->getKey();   
        ro.flush();
        std::string str = ostr.str();


        out << "blkID: "<< blk <<" ";   


        std::stringstream temp_buffer;
        temp_buffer << blk;
        MyBBTable.insert(std::map<std::string, std::string>::value_type(temp_buffer.str(), str));


         
        llvm::dbgs() << str;
        //check if "br" inst in the str?
        std::vector<std::string> strs;
        boost::split(strs, str, boost::is_any_of("\n"));  //get all instructions line by line
        for (std::vector<std::string>::iterator it = strs.begin(); it != strs.end(); ++it) {
        	llvm::dbgs() << "inst: " << *it <<"\n";
        	std::string temp_str = *it;
        	if (temp_str.find("br") != std::string::npos &&  countSubstring(temp_str, "label")>1 ) {  //filter br with more than 2 labels in a line

        		temp_buffer.str("");
        		temp_buffer << blk;
        		//brklist.push_back( temp_buffer.str() );


        		MyBBDependency tempMyBBDependency;
        		tempMyBBDependency.brkbbid = temp_buffer.str();
        		tempMyBBDependency.brkinst = temp_str;
        		//find the location!
        		auto from_itr = InsLocMap.find( trim(temp_str) );
        		tempMyBBDependency.brkloc = from_itr->second;

        		MyBrkList.push_back( tempMyBBDependency );
        		llvm::dbgs() << "find a br  bbid:" << temp_buffer.str() << " brkinst:" << temp_str << " loc:" <<  from_itr->second << "\n";
        	}
        }
        


        unsigned int i = 0;
        unsigned int len = 0;
        while (str[i] != 0) {
            if (len >= 40) {   //the purpose is to maintain the width to 40 char!  Notice here lost some info since it directly replace some char with '\n'!!!
                str[i] = '\n';
                len = 0;
            } else
                ++len;

            if (str[i] == '\n')   //if at the end of the line, just start as a new line
                len = 0;

            ++i;
        }

        unsigned int slice_id = blk->getSlice();
        if (slice_id != 0)
            out << "\\nslice: "<< slice_id << "\\n";
        out << str << "\"";

        if (slice_id != 0)
            out << "style=filled fillcolor=greenyellow";

        out << "]\n";
    }

    void dumpBlockEdges(LLVMBBlock *blk)
    {

		std::stringstream temp_buffer;
        temp_buffer << blk; //block id of blk

        for (const LLVMBBlock::BBlockEdge& edge : blk->successors()) {
            out << "NODE" << blk << " -> NODE" << edge.target
                << " [penwidth=2 color=darkgreen label=\""<< (int) edge.label << "\"] \n";   

			std::stringstream temp_buffer2;
       		temp_buffer2 << edge.target;   //block id of edge.target
             
            for(int t=0;t<MyBrkList.size();++t) {
            	if (  MyBrkList[t].brkbbid  == temp_buffer.str() ) {
            		llvm::dbgs() << "find a br Control, " << "NODE" << blk << " -> NODE" << edge.target << " label="<< (int) edge.label << "\n";

            		//MyBrkList[t].tobbid = temp_buffer2.str();
            		//MyBrkList[t].label = (int) edge.label;
            		MyBBDependency tempMyBBDependency;
            		tempMyBBDependency.brkbbid = MyBrkList[t].brkbbid;
            		tempMyBBDependency.brkinst = MyBrkList[t].brkinst;
            		tempMyBBDependency.brkloc = MyBrkList[t].brkloc;
            		tempMyBBDependency.tobbid = temp_buffer2.str();
            		tempMyBBDependency.label = (int) edge.label;
            		MyBBDependencyList.push_back( tempMyBBDependency );

            		//given a new blk: check if blk contains the event function (by checking the MyBBTable) && edge.label==1 && edge.target contains event-triggering function (still checking MyBBTable)
					//if yes, find an event-action pair, then push_back to MyEventActionList
					if ((int) edge.label == 0) {  //only consider the True case!
						std::map<std::string, std::string>::iterator itr = MyBBTable.find(temp_buffer.str());   //get the instruction list
						std::map<std::string, std::string>::iterator itr2 = MyBBTable.find(temp_buffer2.str());
						if ( itr != MyBBTable.end() &&  itr2 != MyBBTable.end() )
						{
							llvm::dbgs() << "MyBBTable hit the key (blkids): "<< temp_buffer.str() <<  " and " <<temp_buffer2.str() <<"\n";

							std::string InstList=itr->second;
							std::string InstList2=itr2->second;
							replace(InstList.begin(), InstList.end(), '\n', '#');
							replace(InstList2.begin(), InstList2.end(), '\n', '#');
							llvm::dbgs() << "List of inst: "<< InstList <<"\n";
							llvm::dbgs() << "List of inst: "<< InstList2 <<"\n";
							int eventIndex=isContainEvent(InstList);
							int actionIndex=isContainAction(InstList2);
							if (eventIndex>=0 && actionIndex>=0) {
								llvm::dbgs() << "find an event-action pair " << EventList[eventIndex] <<" triggers "<< ActionList[actionIndex] << "\n";
								EventAction tempEventAction;
								tempEventAction.afunc = ActionList[actionIndex];
    							tempEventAction.afuncId = actionIndex;
    							Event tempEvent;
   								tempEvent.efunc = EventList[eventIndex];
    							tempEvent.efuncId = eventIndex;
    							tempEvent.flag = true;
    							tempEventAction.eventlist.push_back(tempEvent);
								//backwardly retrieve MyBBDependencyList to deal with the nested conditions. given block id that contains an event
								llvm::dbgs() << "backwardly retrieve MyBBDependencyList to deal with the nested conditions, start with "<< MyBrkList[t].brkbbid <<"\n";
								BackwardSearchBBDependency(tempEventAction, MyBrkList[t].brkbbid);  //fill missing info into  tempEventAction
								//then keep the info in MyEventActionList
								MyEventActionList.push_back(tempEventAction);
							}
						}
					}
            	}
            }

        }

        for (const LLVMBBlock *pdf : blk->controlDependence()) {
            out << "NODE" << blk << " -> NODE" << pdf
                << " [penwidth=3  color=darkorange constraint=false]\n";   
        }
    }
};
} /* namespace debug */
} /* namespace dg */
