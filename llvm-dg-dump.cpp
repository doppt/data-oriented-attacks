#ifndef HAVE_LLVM
#error "This code needs LLVM enabled"
#endif

#include <set>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

#include <cassert>
#include <cstdio>

// ignore unused parameters in LLVM libraries
#if (__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#include <llvm/IR/Module.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/IRReader/IRReader.h>

 
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <vector>
#include <set>
 

#if LLVM_VERSION_MAJOR >= 4
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#else
#include <llvm/Bitcode/ReaderWriter.h>
#endif

#if (__clang__)
#pragma clang diagnostic pop // ignore -Wunused-parameter
#else
#pragma GCC diagnostic pop
#endif

#include "llvm/LLVMDependenceGraph.h"
#include "llvm/Slicer.h"
#include "llvm/LLVMDG2Dot.h"
#include "TimeMeasure.h"

#include "llvm/analysis/DefUse.h"
#include "llvm/analysis/PointsTo/PointsTo.h"
#include "llvm/analysis/ReachingDefinitions/ReachingDefinitions.h"

#include "analysis/PointsTo/PointsToFlowSensitive.h"
#include "analysis/PointsTo/PointsToFlowInsensitive.h"


#include <llvm/Config/llvm-config.h>
#if (LLVM_VERSION_MINOR < 5)
 #include <llvm/DebugInfo.h>
#else
 #include <llvm/DebugInfo/DIContext.h>
#endif

#include <map>



using namespace dg;
using llvm::errs;


extern std::map < std::string, std::string > InsLocMap;  //initiated in llvm-dg-dump.cpp
extern std::vector<FuncArg> FunctionList;
extern std::map<std::string, std::set<std::string> > callgraph;



std::vector<std::string> split(std::string str,std::string pattern)
{
    std::string::size_type pos;
    std::vector<std::string> result;
    str+=pattern;
    int size=str.size();

    for(int i=0; i<size; i++)
    {
        pos=str.find(pattern,i);
        if(pos<size)
        {
            std::string s=str.substr(i,pos-i);
            result.push_back(s);
            i=pos+pattern.size()-1;
        }
    }
    return result;
}

void dumpCallGraph() {
	for (std::map<std::string, std::set<std::string> >::iterator i = callgraph.begin(); i != callgraph.end(); i++) {
		llvm::dbgs() << "[callgraph] [" << i->first << "]: ";
		int j = 0; 
		int n = i->second.size();
		for (std::set<std::string>::iterator ii = i->second.begin(); ii != i->second.end(); ++ii) {
			llvm::dbgs() << "[" << *ii << "]";
			if (j != n-1) 
				llvm::dbgs() << ", ";
                       	else llvm::dbgs() << "\n";
                                j++;
                }
	}
}

void buildCallGraph( llvm::Module *M ) {

	for (const llvm::Function& F : *M) {

		std::string callerName = F.getName();
                std::map< std::string, std::set<std::string> > fpointers;
                std::map< std::string, std::string> defpointer;

		for (const llvm::BasicBlock& B : F) {

        		for (const llvm::Instruction& I : B) {
				
				if (auto* call = llvm::dyn_cast<llvm::CallInst>(&I)) {
					//also record the line # of callsite
			                const llvm::DebugLoc &location = I.getDebugLoc();
			                std::string type_str;
			                llvm::raw_string_ostream rso(type_str);
			                location.print(rso);
			                //std::string trimed_str_inst= trim(str_inst);
			                std::string locfunc= rso.str();
			               					///get loc end
					if (auto* fun = call->getCalledFunction()) {
						std::string calleeName = fun->getName();
						//add the callsite line#
						callgraph[callerName].insert(calleeName+"#"+rso.str());
					}
					else {
						auto* var = call->getCalledValue();
						std::string label = var->getName();
						for(std::set<std::string>::iterator i = fpointers[defpointer[label]].begin(); i != fpointers[defpointer[label]].end(); ++i)
						{
							//add the callsite line#
							callgraph[callerName].insert(*i+"#"+rso.str());
						}
					}
				}
				else if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&I)) {
					std::string valueName   = store->getValueOperand()->stripPointerCasts()->getName();
					std::string pointerName = store->getPointerOperand()->getName();
					fpointers[pointerName].insert(valueName);
					for (auto* U : store->getPointerOperand()->users()) {
                                        	if (auto* Inst = llvm::dyn_cast<llvm::Instruction>(U)) {
							if (auto* load = llvm::dyn_cast<llvm::LoadInst>(Inst)) {
								std::string label = load->getName();
								defpointer[label] = pointerName;
							}
						}
					}
				}
			}
		}
	}
	return; 
}



  


int main(int argc, char *argv[])
{
    llvm::Module *M;
    llvm::LLVMContext context;
    llvm::SMDiagnostic SMD;
    bool mark_only = false;
    bool bb_only = false;
    const char *module = nullptr;
    const char *slicing_criterion = nullptr;
    const char *dump_func_only = nullptr;
    const char *pts = "fi";
    CD_ALG cd_alg = CLASSIC;

    using namespace debug;
    uint32_t opts = PRINT_CFG | PRINT_DD | PRINT_CD;

    // parse options
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-no-control") == 0) {
            opts &= ~PRINT_CD;
        } else if (strcmp(argv[i], "-pta") == 0) {
            pts = argv[++i];
        } else if (strcmp(argv[i], "-no-data") == 0) {
            opts &= ~PRINT_DD;
        } else if (strcmp(argv[i], "-nocfg") == 0) {
            opts &= ~PRINT_CFG;
        } else if (strcmp(argv[i], "-call") == 0) {
            opts |= PRINT_CALL;
        } else if (strcmp(argv[i], "-postdom") == 0) {
            opts |= PRINT_POSTDOM;
        } else if (strcmp(argv[i], "-bb-only") == 0) {
            bb_only = true;
        } else if (strcmp(argv[i], "-cfgall") == 0) {
            opts |= PRINT_CFG;
            opts |= PRINT_REV_CFG;
        } else if (strcmp(argv[i], "-func") == 0) {
            dump_func_only = argv[++i];
        } else if (strcmp(argv[i], "-slice") == 0) {
            slicing_criterion = argv[++i];
        } else if (strcmp(argv[i], "-mark") == 0) {
            mark_only = true;
            slicing_criterion = argv[++i];
        } else if (strcmp(argv[i], "-cd-alg") == 0) {
            const char *arg = argv[++i];
            if (strcmp(arg, "classic") == 0)
                cd_alg = CLASSIC;
            else if (strcmp(arg, "ce") == 0)
                cd_alg = CONTROL_EXPRESSION;
            else {
                errs() << "Invalid control dependencies algorithm, try: classic, ce\n";
                abort();
            }

        } else {
            module = argv[i];
        }
    }

    if (!module) {
        errs() << "Usage: % IR_module [output_file]\n";
        return 1;
    }

#if ((LLVM_VERSION_MAJOR == 3) && (LLVM_VERSION_MINOR <= 5))
    M = llvm::ParseIRFile(module, SMD, context);
#else
    auto _M = llvm::parseIRFile(module, SMD, context);
    // _M is unique pointer, we need to get Module *
    M = _M.get();
#endif

    if (!M) {
        llvm::errs() << "Failed parsing '" << module << "' file:\n";
        SMD.print(argv[0], errs());
        return 1;
    }

    int count=0;
    std::set<unsigned> lines;

    //first fill the FunctionList!
    std::string previous_filename="";


    for (const llvm::Function& F : *M) {
	
	//just break
	//break;

	FuncArg tempFuncArg;
        tempFuncArg.funcname = F.getName();

        
	for(auto arg = F.arg_begin(); arg != F.arg_end(); ++arg) {
                std::string type_str;
                llvm::raw_string_ostream rso(type_str);
                arg->print(rso);
                tempFuncArg.arglist.push_back(rso.str());
        }


        std::string filename=""; 
	for (const llvm::BasicBlock& B : F) {
       	    for (const llvm::Instruction& inst : B) {
	
		const llvm::DebugLoc &location = inst.getDebugLoc();
		std::string type_str;
                llvm::raw_string_ostream rso(type_str);
                location.print(rso);

                std::string locfunc= rso.str();
       		std::vector<std::string> tempvec;
                boost::split(tempvec, locfunc, boost::is_any_of(":"), boost::token_compress_on);

		if (tempvec.size()>0)  {

			filename = tempvec[0];
			
			break;
		}          
    	    }
	    if ( filename != "" ) {
		previous_filename = filename;
		break;
	    }
	}
	if ( filename != "" ) {
		//llvm::dbgs() << "function name: " << F.getName() << "  filename:"  <<  filename << "\n";
	        tempFuncArg.filename = filename;
	} else {
		//llvm::dbgs() << "function name: " << F.getName() << "  filename:"  <<  previous_filename << "\n";
		tempFuncArg.filename = previous_filename;
	}
        //llvm::dbgs() << "filename:"  <<  filename  << "\n";
        FunctionList.push_back(tempFuncArg);
    }

  
    
    for (const llvm::Function& F : *M) {
	
        for (const llvm::BasicBlock& B : F) {
            for (const llvm::Instruction& inst : B) {

           	
            	debug::TimeMeasure tm2;

            	std::string str_inst;
            	llvm::raw_string_ostream rso_inst(str_inst);
            	inst.print(rso_inst);
            	str_inst = rso_inst.str();

            	const llvm::DebugLoc &location = inst.getDebugLoc();

		std::string type_str;
		llvm::raw_string_ostream rso(type_str);
		location.print(rso);

		std::string trimed_str_inst= trim(str_inst);
		std::string locfunc= rso.str();  
		locfunc += "#";
		locfunc +=  F.getName();
		locfunc += "#";
                locfunc +=  B.getName().data();
		
		trimed_str_inst += " ";
		trimed_str_inst += F.getName();	
	
		if(InsLocMap.insert(std::make_pair(trimed_str_inst, locfunc)).second == false)
		{
			errs() << "Insertion failed. Key was present: "  <<  trimed_str_inst  << " ###Loc: " << locfunc  << " \n";
		}
		else {
			llvm::dbgs() << "Instruction: "<< trimed_str_inst  << " ###Loc: " << locfunc << "\n";
		}

            }
        }
    }
 

    debug::TimeMeasure tm;

    // TODO refactor the code...
    LLVMDependenceGraph d;
    LLVMPointerAnalysis *PTA = new LLVMPointerAnalysis(M);

    if (strcmp(pts, "fs") == 0) {
        tm.start();
        PTA->run<analysis::pta::PointsToFlowSensitive>();
        tm.stop();
    } else if (strcmp(pts, "fi") == 0) {
        tm.start();
        PTA->run<analysis::pta::PointsToFlowInsensitive>();
        tm.stop();
    } else {
        llvm::errs() << "Unknown points to analysis, try: fs, fi\n";
        abort();
    }

    //return 0;
    tm.report("INFO: Points-to analysis took");

    d.build(M, PTA);

    std::set<LLVMNode *> callsites;
    if (slicing_criterion) {
        const char *sc[] = {
            slicing_criterion,
            "klee_assume",
            NULL
        };

        tm.start();
        d.getCallSites(sc, &callsites);
        tm.stop();
        tm.report("INFO: Finding slicing criterions took");
    }

    assert(PTA && "BUG: Need points-to analysis");
    //use new analyses
 
    analysis::rd::LLVMReachingDefinitions RDA(M, PTA);
    tm.start();
    RDA.run();  // compute reaching definitions
    tm.stop();
    tm.report("INFO: Reaching defs analysis took");

    LLVMDefUseAnalysis DUA(&d, &RDA, PTA);
    tm.start();
    DUA.run(); // add def-use edges according that
    tm.stop();
    tm.report("INFO: Adding Def-Use edges took");

    // we won't need PTA anymore
    delete PTA;

    tm.start();
    // add post-dominator frontiers
    d.computeControlDependencies(cd_alg);
    tm.stop();
    tm.report("INFO: computing control dependencies took");

    if (slicing_criterion) {
        LLVMSlicer slicer;
        tm.start();

        if (strcmp(slicing_criterion, "ret") == 0) {
            if (mark_only)
                slicer.mark(d.getExit());
            else
                slicer.slice(&d, d.getExit());
        } else {
            if (callsites.empty()) {
                errs() << "ERR: slicing criterion not found: "
                       << slicing_criterion << "\n";
                exit(1);
            }

            uint32_t slid = 0;
            for (LLVMNode *start : callsites)
                slid = slicer.mark(start, slid);

            if (!mark_only)
               slicer.slice(&d, nullptr, slid);
        }

        // there's overhead but nevermind
        tm.stop();
        tm.report("INFO: Slicing took");

        if (!mark_only) {
            std::string fl(module);
            fl.append(".sliced");
            std::ofstream ofs(fl);
            llvm::raw_os_ostream output(ofs);

            analysis::SlicerStatistics& st = slicer.getStatistics();
            errs() << "INFO: Sliced away " << st.nodesRemoved
                   << " from " << st.nodesTotal << " nodes\n";

            llvm::WriteBitcodeToFile(M, output);
        }
    }

    LLVMDG2Dot dumper2(&d, opts);

    //dumper.dump(nullptr, dump_func_only);   //bb_only
    dumper2.dump(nullptr, dump_func_only);
    //dumper2.initialize_detectability_analysis();
    //dumper2.dopgadget_analysis();
    dumper2.BB_Correlation_Analysis();   
    return 0;
}
