// Applies the fact files written by tools/*.py (build/facts/*.json) to the program.
// Re-runnable: names are applied as IMPORTED and never replace a USER_DEFINED name,
// tags and comments are idempotent.
//
// Usage (headless): -postScript ApplyFacts.java <facts dir>
//@category Rhipper
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.framework.Application;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ApplyFacts extends GhidraScript {
    private SymbolTable symbols;
    private int named, kept, created, tagged, labelled;
    private final Map<Address, String> helperAt = new HashMap<>();
    // the variadic functions' fixed parameter counts (varargs.json), for applyProtos
    private final Map<Address, Integer> vaFixed = new HashMap<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File dir = new File(args.length > 0 ? args[0] : "build/facts");
        symbols = currentProgram.getSymbolTable();

        // first, so no other fact lands on a function that is part of another
        File pc = new File(dir, "pieces.json");
        if (pc.exists()) applyPieces(read(pc));
        File lua = new File(dir, "luabind.json");
        if (lua.exists()) applyLua(read(lua));
        // C_ namespaces registered in code (same "functions" map: "C_X.Name" -> handler)
        File creg = new File(dir, "cregister.json");
        if (creg.exists()) applyLua(read(creg));
        File vt = new File(dir, "vtables.json");
        if (vt.exists()) applyVtables(read(vt));
        repairBodies();
        File src = new File(dir, "srcrefs.json");
        if (src.exists()) applySrcrefs(read(src));
        File imp = new File(dir, "imports.json");
        if (imp.exists()) applyImports(read(imp));
        File tags = new File(dir, "typetags.json");
        if (tags.exists()) applyTypeTags(read(tags));
        File rc = new File(dir, "retcheck.json");
        if (rc.exists()) applyRetcheck(read(rc));
        File nr = new File(dir, "noreturn.json");
        if (nr.exists()) applyNoReturn(read(nr));
        applyAtomicVolatile();
        File va = new File(dir, "varargs.json");
        if (va.exists()) applyVarargs(read(va));
        // after the varargs (which keep their own fixed count)
        File sw = new File(dir, "switches.json");
        if (sw.exists()) applySwitches(read(sw));
        // (read before the prototypes, which give each function its keep convention)
        File pv = new File(dir, "preserved.json");
        if (pv.exists()) {
            JsonObject pvRoot = read(pv);
            // (with 'needed' in the file, its 'functions' are the chosen conventions, xmm0 among
            // them where a caller relies on it: protos.py's keep_xmm0 is folded in already)
            preservedChosen = pvRoot.has("needed");
            for (Map.Entry<String, JsonElement> e : pvRoot.getAsJsonObject("functions").entrySet()) {
                java.util.List<String> regs = new ArrayList<>();
                for (JsonElement r : e.getValue().getAsJsonArray()) regs.add(r.getAsString());
                preserved.put(addr(e.getKey()), regs);
            }
        }
        // (before the prototypes, which pin these positions to integer types)
        File ip = new File(dir, "intparams.json");
        if (ip.exists()) {
            for (Map.Entry<String, JsonElement> e : read(ip).getAsJsonObject("functions").entrySet()) {
                Set<Integer> at = new java.util.HashSet<>();
                for (JsonElement k : e.getValue().getAsJsonArray()) at.add(k.getAsInt());
                intParams.put(addr(e.getKey()), at);
            }
        }
        // structure layouts for the types Ghidra has as placeholders (the project's data/structs.json):
        // before the prototypes, which name them
        File st = new File(dir, "structs.json");
        if (st.exists()) applyStructs(read(st));
        // (the compiler's helpers identified by running them, for their call fixups: applyLongHelpers32)
        File hp = new File(dir, "helpers32.json");
        if (hp.exists()) {
            for (Map.Entry<String, JsonElement> e : read(hp).getAsJsonObject("helpers").entrySet())
                helperAt.put(addr(e.getKey()), e.getValue().getAsString());
        }
        File pr = new File(dir, "protos.json");
        if (pr.exists() && "x86".equals(jsonString(read(pr), "arch"))) {
            // 32-bit (protos32.py): a convention per function, or register storage of its own
            JsonObject protos = read(pr);
            applyProtos32(protos);
            applyEhHandlerImports();
            constantCallSlots32();
            if (protos.has("stack_blocks")) applyStackBlocks(protos.getAsJsonObject("stack_blocks"), true);
        } else if (pr.exists()) {
            JsonObject protos = read(pr);
            applyProtos(protos);
            applyIntParamHomes(protos.getAsJsonObject("functions"));
            if (protos.has("stack_blocks")) applyStackBlocks(protos.getAsJsonObject("stack_blocks"), false);
        }
        File cs = new File(dir, "callsites.json");
        if (cs.exists()) applyCallsites(read(cs));
        // (the static C runtime's functions by their bytes, crtsigs.py: first, RTTI's and the hand
        // names after them winning)
        File crt = new File(dir, "names_crt.json");
        if (crt.exists()) applyNames(read(crt));
        // (an x86 binary's virtual functions by their RTTI classes, rtti32.py: before the hand
        // names, which win)
        File rtti = new File(dir, "names_rtti.json");
        if (rtti.exists()) applyNames(read(rtti));
        // hand-identified names last, so they win over anything extracted
        File names = new File(dir, "names.json");
        if (names.exists()) applyNames(read(names));
        // after the names and varargs, so each slot takes its target's final signature
        File fp = new File(dir, "funcptrs.json");
        if (fp.exists()) applyFuncptrs(read(fp));
        // after the function-pointer slots, which keep their signature types
        File gp = new File(dir, "globalptrs.json");
        if (gp.exists()) applyGlobalPtrs(read(gp));
        uniqueNames();

        println(String.format("ApplyFacts: named %d (kept %d user names), created %d functions, " +
                "tagged %d, labelled %d vtables", named, kept, created, tagged, labelled));
    }

    private JsonObject read(File f) throws Exception {
        return JsonParser.parseString(Files.readString(f.toPath())).getAsJsonObject();
    }

    private static String jsonString(JsonObject o, String key) {
        return o.has(key) ? o.get(key).getAsString() : null;
    }

    // protos.json from protos32.py: "cc" __cdecl / __stdcall / __thiscall / __fastcall, given with
    // dynamic storage and one undefined4 per parameter, or "custom": the registers in "regs", then the stack
    // from entry + 4, as custom storage under __stdcall (callee cleans) or __cdecl. A signature
    // someone set by hand or that came with a library match (USER_DEFINED, IMPORTED) is kept, and
    // so are thunks, whose signature is their target's.
    // Each direct jump from a function to another's entry, outside its own body: a call that
    // returns (the jumper's tail call). Left a branch, the decompiler followed it and decompiled
    // the callee into the caller: FUN_00def610's `jmp FUN_00dedcf0`, hkVersionPatchManager's
    // constructor, came out inline, its allocator call without the `this` its own call-site
    // signature gives it, and the port called the allocator with 0x2c for its object (a VS2010
    // client, 2026-10-25). protos.py lists x64's (applyCallsites' "tail_jumps"); protos32.py lists none.
    private void tailJumps32() {
        int marked = 0, kept = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            if (!insn.getFlowType().isUnConditional() || !insn.getFlowType().isJump() || insn.getFlowType().isComputed()) continue;
            Address[] flows = insn.getFlows();
            if (flows.length != 1) continue;
            Function target = getFunctionAt(flows[0]);
            Function self = getFunctionContaining(insn.getAddress());
            if (target == null || self == null || target.equals(self) || self.isThunk()
                    || self.getBody().contains(flows[0])) continue;
            if (insn.getFlowOverride() == FlowOverride.CALL_RETURN) {
                kept++;
                continue;
            }
            insn.setFlowOverride(FlowOverride.CALL_RETURN);
            marked++;
        }
        println(String.format("ApplyFacts: x86 tail jumps marked calls that return %d (%d already)", marked, kept));
    }

    private void applyProtos32(JsonObject root) throws Exception {
        // (the code Ghidra's analysis never reached, made functions first: their prototypes come
        // on protos32.py's next run, over the extents `ghidra.sh functions` then exports)
        applyLeaves(root);
        cleanFunctions32();
        tailJumps32();
        int set = 0, keptSig = 0, missing = 0, failed = 0, custom = 0, keeps = 0;
        DataType u4 = Undefined.getUndefinedDataType(4);
        // the keep conventions the functions need (protos32.py "keep"), each made once
        java.util.Set<String> keepNames = new java.util.TreeSet<>();
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            JsonObject o = e.getValue().getAsJsonObject();
            if (o.has("keep")) keepNames.add(keepName32(keepBase32(o), o.getAsJsonArray("keep")));
        }
        if (!keepNames.isEmpty()) addKeepConventions32(keepNames);
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) {
                missing++;
                continue;
            }
            SourceType src = f.getSignatureSource();
            JsonObject o = e.getValue().getAsJsonObject();
            String cc = o.get("cc").getAsString();
            // (a library match's signature is the library's, not this build's register convention:
            // the CRT's parse_cmdline takes its command line in edi, which the matched signature
            // has no place for, and its body read `unaff_EDI`. A register convention found in the
            // code wins over it; a hand-set one never loses)
            boolean libraryButCustom = src == SourceType.IMPORTED && cc.equals("custom");
            // (and one whose code reads more of the stack than the library's signature has: this
            // build's ___crtGetStringTypeA takes eight, the matched signature seven, and the eighth
            // read was `in_stack_00000020`, a stub, 2026-10-24)
            int libStack = 0;
            // (or whose parameters Ghidra laid out with a gap: a longlong aligned to 8, at 12 after a
            // 4-byte one at 4, where MSVC's x86 code packs it at 8. __lseeki64_nolock(fh, 0, 2) read
            // as (fh, 0x200000000, <the caller's next word>), _tsopen_nolock a stub for it and
            // fopen dead in a VS2010 client, 2026-10-24)
            boolean libraryGap = false;
            int expect = 4;
            for (ghidra.program.model.listing.Parameter p : f.getParameters()) {
                if (!p.isStackVariable()) continue;
                libStack += (p.getLength() + 3) & ~3;
                if (p.getStackOffset() != expect) libraryGap = true;
                expect = p.getStackOffset() + ((p.getLength() + 3) & ~3);
            }
            boolean libraryShort = src == SourceType.IMPORTED && !f.hasVarArgs()
                    && (o.get("stack").getAsInt() > libStack || libraryGap);
            if (f.isThunk() || src == SourceType.USER_DEFINED
                    || (src == SourceType.IMPORTED && !libraryButCustom && !libraryShort)) {
                keptSig++;
                continue;
            }
            int stack = o.get("stack").getAsInt();
            List<Variable> params = new ArrayList<>();
            try {
                if (cc.equals("custom")) {
                    for (JsonElement r : o.getAsJsonArray("regs")) {
                        String reg = r.getAsString();
                        // (an xmm register: a float, in its low lane, as /LTCG passes one)
                        boolean xmm = reg.startsWith("xmm"), st = reg.equals("st0");
                        // (`xmm2d`: a double in its low 8 bytes, protos32.py's for an `sd` read)
                        boolean dbl = xmm && reg.endsWith("d");
                        if (dbl) reg = reg.substring(0, reg.length() - 1);
                        String rn = xmm ? reg.toUpperCase() + (dbl ? "_Qa" : "_Da") : reg.toUpperCase();
                        // (a part of a register, `cl`, at its own size: protos32.py names an input
                        // by the width its reads take, the CRT's 64-bit shifts' count in cl)
                        DataType pt = dbl ? ghidra.program.model.data.DoubleDataType.dataType
                                : xmm ? ghidra.program.model.data.FloatDataType.dataType
                                : st ? ghidra.program.model.data.Float10DataType.dataType
                                : Undefined.getUndefinedDataType(currentProgram.getRegister(rn).getMinimumByteSize());
                        params.add(new ParameterImpl("in_" + reg, pt, new ghidra.program.model.listing.VariableStorage(
                                currentProgram, currentProgram.getRegister(rn)), currentProgram));
                    }
                    int off = 4;
                    for (DataType t : stackTypes32(o, o.getAsJsonArray("regs").size(), stack)) {
                        params.add(new ParameterImpl("param_" + (params.size() + 1), t,
                                new ghidra.program.model.listing.VariableStorage(currentProgram, off, t.getLength()),
                                currentProgram));
                        off += t.getLength();
                    }
                    boolean callee = o.get("callee_cleans").getAsBoolean() && stack > 0;
                    f.updateFunction(callee ? "__stdcall" : "__cdecl", f.getReturn(), params,
                            FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
                    custom++;
                } else {
                    // (the list names every parameter, register ones included: under dynamic storage
                    // __thiscall's first is `this`, in ecx, and __fastcall's first two ecx and edx)
                    int nreg = cc.equals("__fastcall") ? 2 : cc.equals("__thiscall") ? 1 : 0;
                    List<DataType> st = stackTypes32(o, nreg, stack);
                    boolean floats = st.stream().anyMatch(t -> t.getLength() != 4 || !(t instanceof Undefined));
                    if (!floats) {
                        for (int i = 0; i < nreg; i++) params.add(new ParameterImpl("param_" + (i + 1), u4, currentProgram));
                        for (DataType t : st)
                            params.add(new ParameterImpl("param_" + (params.size() + 1), t, currentProgram));
                        f.updateFunction(cc, null, params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                                SourceType.ANALYSIS);
                    } else {
                        // (a float or double parameter at the offset its reads take: the convention's
                        // own storage aligns a double to 8, and `dmix(float, double, int)` read its
                        // double at [esp + 0xc] for [esp + 8], in_stack_00000008, rhtest float)
                        String[] regs = {"ECX", "EDX"};
                        for (int i = 0; i < nreg; i++) {
                            params.add(new ParameterImpl("param_" + (i + 1), u4, new ghidra.program.model.listing
                                    .VariableStorage(currentProgram, currentProgram.getRegister(regs[i])), currentProgram));
                        }
                        int off = 4;
                        for (DataType t : st) {
                            params.add(new ParameterImpl("param_" + (params.size() + 1), t,
                                    new ghidra.program.model.listing.VariableStorage(currentProgram, off, t.getLength()),
                                    currentProgram));
                            off += t.getLength();
                        }
                        f.updateFunction(cc, f.getReturn(), params, FunctionUpdateType.CUSTOM_STORAGE, true,
                                SourceType.ANALYSIS);
                    }
                }
                // (variadic: its fixed parameters above, and each call site's own beyond them, so a
                // caller passes what it pushes, protos32.py's va_start of the slot past them)
                if (o.has("variadic") != f.hasVarArgs()) f.setVarArgs(o.has("variadic"));
                if (o.has("ret")) setReturn32(f, o.get("ret").getAsString());
                // (a float result the facts do not give it is an earlier round's: void. xmm0 returns
                // spread through wrappers left FUN_004c67d0 a float the facts no longer give, and
                // the project keeps it, 2026-10-24)
                else if (f.getReturnType() instanceof ghidra.program.model.data.AbstractFloatDataType) {
                    if (f.hasCustomVariableStorage()) {
                        f.setReturn(ghidra.program.model.data.VoidDataType.dataType,
                                ghidra.program.model.listing.VariableStorage.VOID_STORAGE, SourceType.ANALYSIS);
                    } else {
                        f.setReturnType(ghidra.program.model.data.VoidDataType.dataType, SourceType.ANALYSIS);
                    }
                }
                if (o.has("keep")) {
                    // (a custom one's storage stays its own: the convention only says what it keeps)
                    f.setCallingConvention(keepName32(keepBase32(o), o.getAsJsonArray("keep")));
                    keeps++;
                    // (one that leaves eax alone returns nothing in it: void, whatever an earlier
                    // round typed. __security_check_cookie kept the ulonglong it had, and its 7,155
                    // callers returned that, not the eax they had set, 2026-10-24)
                    // (but for its result in ecx, "c4", which keeps eax alone)
                    if (o.getAsJsonArray("keep").contains(new com.google.gson.JsonPrimitive("eax"))
                            && !(o.has("ret") && java.util.Arrays.asList("c4", "si4", "di4", "bx4")
                                    .contains(o.get("ret").getAsString()))
                            && !(f.getReturnType() instanceof ghidra.program.model.data.VoidDataType)) {
                        f.setReturnType(ghidra.program.model.data.VoidDataType.dataType, SourceType.ANALYSIS);
                    }
                }
                set++;
            } catch (Exception ex) {
                if (failed++ < 5) printerr("ApplyFacts: prototype for " + f.getEntryPoint() + ": " + ex);
            }
        }
        println("ApplyFacts: x86 prototypes set " + set + " (" + custom + " custom storage, " + returnsSet
                + " returns typed, " + keeps + " with registers kept, " + keepNames.size() + " keep conventions), kept " + keptSig
                + " (thunks, hand-set or library), no function " + missing + ", failed " + failed);
        if (root.has("imports")) applyImportArgs32(root.getAsJsonObject("imports"));
        splitWideImportArgs32();
        applyLibmSse2_32();
        applyLongHelpers32();
    }

    // An import's 8-byte argument by value (SetFilePointerEx's LARGE_INTEGER): MSVC's x86 caller
    // pushes it as two words in the next two 4-byte slots, but Ghidra's type library storage aligns
    // it to 8, one slot late, and the arguments after it one slot late too. A client's
    // FUN_004fa4b0 read SetFilePointerEx's dwMoveMethod past what was pushed (`unaff_EBX`) and was
    // a stub; its callers elsewhere passed five words to a four-argument import (2026-10-25). Each
    // is split into its low and high words, every argument in its own slot in order: the call
    // passes the words as pushed, and the runtime's adapter (runtime32/Adapters.cpp) joins them.
    // And a __stdcall one's purge set to its words: custom storage keeps the aligned layout's (24
    // for SetFilePointerEx's 20), and a caller's esp after the call was a word off, every later
    // `[esp+k]` the next slot (rhtest misc-O2 file_seek, VS2010, 2026-10-25). Set on every run, an
    // import split by an earlier one too
    private void splitWideImportArgs32() throws Exception {
        DataType u4 = ghidra.program.model.data.DWordDataType.dataType;
        List<String> split = new ArrayList<>();
        int purged = 0;
        for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
            Parameter[] ps = f.getParameters();
            boolean wide = false, already = false;
            for (Parameter p : ps) {
                wide |= wideInteger(p.getDataType());
                already |= f.hasCustomVariableStorage() && p.getName().endsWith("High") && p.getDataType().getLength() == 4;
            }
            if (already && !wide) {
                purged += purgeWords(f);
                continue;
            }
            if (!wide) continue;
            List<Variable> params = new ArrayList<>();
            int off = 4;
            for (Parameter p : ps) {
                DataType t = p.getDataType();
                int len = Math.max(4, (t.getLength() + 3) & ~3);
                if (wideInteger(t)) {
                    params.add(new ParameterImpl(p.getName() + "Low", u4,
                            new ghidra.program.model.listing.VariableStorage(currentProgram, off, 4), currentProgram));
                    params.add(new ParameterImpl(p.getName() + "High", u4,
                            new ghidra.program.model.listing.VariableStorage(currentProgram, off + 4, 4), currentProgram));
                } else {
                    params.add(new ParameterImpl(p.getName(), t,
                            new ghidra.program.model.listing.VariableStorage(currentProgram, off, len), currentProgram));
                }
                off += len;
            }
            Variable ret = new ghidra.program.model.listing.ReturnParameterImpl(f.getReturnType(),
                    f.getReturn().getVariableStorage(), currentProgram);
            f.updateFunction(f.getCallingConventionName(), ret, params, FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED);
            purged += purgeWords(f);
            split.add(f.getName());
        }
        println("ApplyFacts: imports with an 8-byte argument split into two words " + split.size() + " " + split
                + ", purges set " + purged);
    }

    // a __stdcall function's purge as its stack arguments' slots; 1 if it changed
    private static int purgeWords(Function f) throws Exception {
        if (!"__stdcall".equals(f.getCallingConventionName())) return 0;
        int end = 4;
        for (Parameter p : f.getParameters())
            if (p.isStackVariable()) end = Math.max(end, p.getStackOffset() + Math.max(4, (p.getLength() + 3) & ~3));
        int purge = end - 4;
        if (f.getStackPurgeSize() == purge) return 0;
        f.setStackPurgeSize(purge);
        return 1;
    }

    // an 8-byte integer or structure (a double is the math imports' own, typed by translate32.py)
    private static boolean wideInteger(DataType t) {
        DataType b = t instanceof ghidra.program.model.data.TypeDef td ? td.getBaseDataType() : t;
        return t.getLength() == 8 && !(b instanceof Pointer) && !(b instanceof ghidra.program.model.data.AbstractFloatDataType);
    }

    // MSVC's x86 64-bit helpers (llmul.asm, lldiv.asm, ...): conventions of their own, values in
    // edx:eax and on the stack (the callee pops 16 bytes), a shift count in cl, __alldvrm's
    // remainder in ebx:ecx. Each is a call fixup: its p-code at every call site, so the caller
    // decompiles to the 64-bit operation itself. As calls, divmod64's remainder was `in_ebx` and
    // `extraout_ECX`, and every 64-bit shift's count `CONCAT31(extraout_ECX >> 8, 0x20)` (rhtest
    // int64, 2026-10-24)
    private void applyLongHelpers32() throws Exception {
        // (a fixup runs after the call pushed its return address, as x86win.cspec's alloca_probe
        // and SEH_prolog4 read theirs: the arguments from ESP + 4, and the helper's `ret 16` is
        // ESP + 20. Read from ESP, the first argument was the return address and the stack 4 bytes
        // off: rhtest_run lost seed()'s value, unaff_EBX)
        String args = "p:4 = ESP + 4; lo1:4 = *:4 p; p = ESP + 8; hi1:4 = *:4 p; p = ESP + 12; lo2:4 = *:4 p;\n"
                + "p = ESP + 16; hi2:4 = *:4 p;\n"
                + "a:8 = (zext(hi1) << 32) | zext(lo1); b:8 = (zext(hi2) << 32) | zext(lo2);\n";
        String value = "v:8 = (zext(EDX) << 32) | zext(EAX); c:8 = zext(CL);\n";
        String pop16 = " ESP = ESP + 20;", pop0 = " ESP = ESP + 4;";
        Map<String, String> bodies = new java.util.LinkedHashMap<>();
        bodies.put("allmul", args + "r:8 = a * b; EAX = r:4; EDX = r(4);" + pop16);
        bodies.put("alldiv", args + "r:8 = a s/ b; EAX = r:4; EDX = r(4);" + pop16);
        bodies.put("aulldiv", args + "r:8 = a / b; EAX = r:4; EDX = r(4);" + pop16);
        bodies.put("allrem", args + "r:8 = a s% b; EAX = r:4; EDX = r(4);" + pop16);
        bodies.put("aullrem", args + "r:8 = a % b; EAX = r:4; EDX = r(4);" + pop16);
        bodies.put("alldvrm", args + "q:8 = a s/ b; r:8 = a s% b; EAX = q:4; EDX = q(4); ECX = r:4; EBX = r(4);"
                + pop16);
        bodies.put("aulldvrm", args + "q:8 = a / b; r:8 = a % b; EAX = q:4; EDX = q(4); ECX = r:4; EBX = r(4);"
                + pop16);
        // (a count of 64 or more as the helpers have it, `cmp cl, 64; jae`: 0, or the sign for
        // __allshr. Left to the shift, the C read it as one an x64 shift masks to 6 bits, x << 65 as
        // x << 1, rhtest int64 shl64_big/sar64_big/shr64_big 2026-10-25)
        String inRange = "big:1 = c > 63; zb:8 = zext(big); zs:8 = zext(!big);\n";
        bodies.put("allshl", value + inRange + "v = zs * (v << c); EAX = v:4; EDX = v(4);" + pop0);
        bodies.put("allshr", value + inRange + "v = (zb * (v s>> 63)) + (zs * (v s>> c)); EAX = v:4; EDX = v(4);" + pop0);
        bodies.put("aullshr", value + inRange + "v = zs * (v >> c); EAX = v:4; EDX = v(4);" + pop0);
        // and the floating-point conversions: SSE2's take or give the double in xmm0 and the
        // integer in edx:eax; x87's (_ftol2, _ftoul2) take st0 and pop it. P-code converts only
        // signed integers, so an unsigned one is chosen by the value's top bit (or 2^63)
        String pop87 = " ST0 = ST1; ST1 = ST2; ST2 = ST3; ST3 = ST4; ST4 = ST5; ST5 = ST6; ST6 = ST7;";
        String two63 = "h:8 = 0x4000000000000000; t:8 = int2float(h); two:8 = int2float(2:8); big:8 = t f* two;\n";
        bodies.put("dtol3", "r:8 = trunc(XMM0_Qa); EAX = r:4; EDX = r(4);" + pop0);
        // (every zext into a temporary of its size: sleigh cannot size `int2float(zext(x))`)
        // (and 2^64 or more, the integer indefinite, 0x8000000000000000, as the helper's: the
        // subtracted 2^63 overflowed trunc to it, and 2^63 added on made it 0, rhtest float
        // d2ul_huge 2026-10-25)
        bodies.put("dtoul3", two63 + "hi:1 = XMM0_Qa f>= big; a:8 = trunc(XMM0_Qa); b:8 = trunc(XMM0_Qa f- big);\n"
                + "big2:8 = big f* two; ov:1 = XMM0_Qa f>= big2;\n"
                + "zh:8 = zext(hi); zl:8 = zext(!hi); zo:8 = zext(ov); zn:8 = zext(!ov);\n"
                + "v:8 = (zh * (b + 0x8000000000000000)) + (zl * a);\n"
                + "r:8 = (zo * 0x8000000000000000) + (zn * v); EAX = r:4; EDX = r(4);" + pop0);
        // (the 64-bit integer in edx:ecx, the low half in ecx: __ltod3's `movd xmm0, ecx`)
        bodies.put("ltod3", "v:8 = (zext(EDX) << 32) | zext(ECX); XMM0_Qa = int2float(v);" + pop0);
        bodies.put("ultod3", "v:8 = (zext(EDX) << 32) | zext(ECX); hv:8 = (v >> 1) | (v & 1);\n"
                + "neg:1 = v s< 0; zn:8 = zext(neg); zp:8 = zext(!neg);\n"
                + "f1:8 = int2float(v); f2:8 = int2float(hv) f+ int2float(hv);\n"
                + "XMM0_Qa = (int2float(zn) f* f2) f+ (int2float(zp) f* f1);" + pop0);
        bodies.put("ftol2", "r:8 = trunc(ST0); EAX = r:4; EDX = r(4);" + pop87 + pop0);
        // (_ftol2_sse is (int)double's: cvttsd2si into eax, 32 bits, the integer indefinite past
        // them. As a 64-bit truncation's low word, 7e10 came out 0x4c533c00, rhtest
        // msvc-16.00-x86 float d2i_huge 2026-10-25)
        bodies.put("ftol2_sse", "r:4 = trunc(ST0); EAX = r;" + pop87 + pop0);
        bodies.put("ftoi2", "r:4 = trunc(ST0); EAX = r;" + pop87 + pop0);
        String ftoul = "h:8 = 0x4000000000000000; t:10 = int2float(h); two:10 = int2float(2:8); big:10 = t f* two;\n"
                + "hi:1 = ST0 f>= big; a:8 = trunc(ST0); b:8 = trunc(ST0 f- big); zh:8 = zext(hi); zl:8 = zext(!hi);\n"
                // (2^64 or more: the integer indefinite, as dtoul3's)
                + "big2:10 = big f* two; ov:1 = ST0 f>= big2; zo:8 = zext(ov); zn:8 = zext(!ov);\n"
                + "v:8 = (zh * (b + 0x8000000000000000)) + (zl * a);\n"
                + "r:8 = (zo * 0x8000000000000000) + (zn * v); EAX = r:4; EDX = r(4);" + pop87 + pop0;
        bodies.put("ftoul2", ftoul);
        bodies.put("ftoul2_legacy", ftoul);
        // (the CRT's square roots, imported: x87's in st0, SSE2's in xmm0)
        bodies.put("CIsqrt", "ST0 = sqrt(ST0);" + pop0);
        // (and its power, x in st1 and y in st0, x^y left in st0: p-code has no pow, so a pair of
        // the language's operations nothing else writes together, `fscale(from_bcd(x), y)`, which
        // translate32.py reads as pow(x, y). FBLD's from_bcd never wraps an fscale's operand)
        bodies.put("CIpow", "b:10 = from_bcd(ST1); r:10 = fscale(b, ST0); ST1 = r;" + pop87 + pop0);
        // (and its remainder, x in st1 and y in st0, fmod(x, y) left in st0: FPREM's own p-code, the
        // quotient truncated through 64 bits, which the decompiler writes as plain C. As a call it
        // took st0 alone, x lost, and its dispatch __cintrindisp2 ran into two stubs (in_ST1 lost,
        // fscale undeclared) on a client's graphics setup, 0x4c0790, 2026-10-27)
        bodies.put("CIfmod", "q:10 = ST1 f/ ST0; i:8 = trunc(q); t:10 = int2float(i); r:10 = ST1 f- (t f* ST0); ST1 = r;"
                + pop87 + pop0);
        // (and its arctangent of two, y in st1 and x in st0, atan2(y, x) left in st0: FPATAN's own
        // operation, which translate32.py reads as atan2. Function ID left a client's unnamed,
        // 0xc4d1fa, 59 callers, a graphics setup's reaching __cintrindisp2's stubs, 2026-10-27)
        bodies.put("CIatan2", "r:10 = fpatan(ST1, ST0); ST1 = r;" + pop87 + pop0);
        // (and its sine and cosine, st0 to st0: the language's fsin and fcos, C's sin and cos in
        // Ghidra32.h)
        bodies.put("CIsin", "ST0 = fsin(ST0);" + pop0);
        bodies.put("CIcos", "ST0 = fcos(ST0);" + pop0);
        // (and the library's sqrt, a __cdecl double on the stack, its root pushed: VS2010's _sqrt at
        // /Od, found by helpers32.py; the caller pops the argument)
        String push87 = " ST7 = ST6; ST6 = ST5; ST5 = ST4; ST4 = ST3; ST3 = ST2; ST2 = ST1; ST1 = ST0;";
        bodies.put("sqrt", "p:4 = ESP + 4; d:8 = *:8 p; r:8 = sqrt(d);" + push87 + " ST0 = float2float(r);" + pop0);
        bodies.put("libm_sse2_sqrt_precise", "XMM0_Qa = sqrt(XMM0_Qa);" + pop0);
        // (and the rest of its x87 math, helpers32.py's CIexp... (st0 to st0) and m_exp... (a __cdecl
        // double on the stack): p-code has none of them, so the pair nothing else writes together,
        // `fpatan(from_bcd(x), K)`, K the function by helpers32.py's MATH_CODES, which translate32.py
        // reads back as Ghidra32.h's gen_x87math. As calls, their SSE2 branches' internals were
        // stubs on a client's camera path, 2026-10-27)
        String[] math = { "exp", "log", "log10", "tan", "atan", "asin", "acos", "sinh", "cosh", "tanh", "sin", "cos",
                "floor", "ceil" };
        for (int i = 0; i < math.length; i++) {
            int k = i + 1;
            if (!math[i].equals("sin") && !math[i].equals("cos") && !math[i].equals("floor") && !math[i].equals("ceil"))
                bodies.put("CI" + math[i], "t:10 = from_bcd(ST0); ST0 = fpatan(t, " + k + ":4);" + pop0);
            bodies.put("m_" + math[i], "p:4 = ESP + 4; d:8 = *:8 p; t:8 = from_bcd(d); r:8 = fpatan(t, " + k + ":4);"
                    + push87 + " ST0 = float2float(r);" + pop0);
        }
        Class<?> se = Function.class.getClassLoader().loadClass("ghidra.program.database.SpecExtension");
        Object ext = se.getConstructor(ghidra.program.model.listing.Program.class).newInstance(currentProgram);
        java.lang.reflect.Method add = se.getMethod("addReplaceCompilerSpecExtension", String.class,
                ghidra.util.task.TaskMonitor.class);
        java.util.Set<String> installed = new java.util.HashSet<>();
        for (Map.Entry<String, String> e : bodies.entrySet()) {
            String n = e.getKey();
            String xml = "<callfixup name=\"rh_" + n + "\"><target name=\"__" + n + "\"/><target name=\"_" + n
                    + "\"/><pcode><body><![CDATA[\n" + e.getValue() + "\n]]></body></pcode></callfixup>";
            // (one that does not compile is reported and left out; the session goes on: a sizing
            // error in one aborted every fact after it, rhtest float 2026-10-24)
            try {
                add.invoke(ext, xml, monitor);
                installed.add(n);
            } catch (java.lang.reflect.InvocationTargetException ex) {
                printerr("ApplyFacts: call fixup rh_" + n + " does not compile: " + ex.getCause());
            }
        }
        int set = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            // (and an import's thunk, by the import's name: __CIsqrt)
            String n = f.getName().replaceFirst("^.*::", "").replaceFirst("^_+", "");
            if (installed.contains(n) && !("rh_" + n).equals(f.getCallFixup())) {
                f.setCallFixup("rh_" + n);
                set++;
            }
        }
        // (the ones function ID left unnamed, identified by running them: helpers32.py)
        for (Map.Entry<Address, String> e : helperAt.entrySet()) {
            Function f = getFunctionAt(e.getKey());
            if (f != null && installed.contains(e.getValue()) && !("rh_" + e.getValue()).equals(f.getCallFixup())) {
                f.setCallFixup("rh_" + e.getValue());
                set++;
            }
        }
        // (and a thunk of one, `__ftol2_sse: jmp __ftoi2`, the same)
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            Function t = f.isThunk() ? f.getThunkedFunction(true) : null;
            if (t != null && t.getCallFixup() != null && t.getCallFixup().startsWith("rh_")
                    && !t.getCallFixup().equals(f.getCallFixup())) {
                f.setCallFixup(t.getCallFixup());
                set++;
            }
        }
        println("ApplyFacts: 64-bit and float helper call fixups set " + set);
    }

    // A function's stack parameters as protos32.py read them ("params" after its `nreg` register
    // ones): a slot read as a double one 8-byte parameter, as a float a float, else 4 bytes. All
    // 4-byte integers, a double was two and the decompiler read it `*(double *)&param_3` (rhtest
    // float, 2026-10-24); without "params", `stack` bytes of them
    private List<DataType> stackTypes32(JsonObject o, int nreg, int stack) {
        DataType u4 = Undefined.getUndefinedDataType(4);
        List<DataType> out = new ArrayList<>();
        JsonArray ps = o.has("params") ? o.getAsJsonArray("params") : null;
        int bytes = 0;
        if (ps != null) {
            for (int i = nreg; i < ps.size() && bytes < stack; i++) {
                String k = ps.get(i).getAsJsonArray().get(0).getAsString();
                DataType t = k.equals("d") ? ghidra.program.model.data.DoubleDataType.dataType
                        : k.equals("f") ? ghidra.program.model.data.FloatDataType.dataType
                        : k.equals("n") ? concreteInt(4) : u4;
                out.add(t);
                bytes += t.getLength();
            }
        }
        for (; bytes < stack; bytes += 4) out.add(u4);
        return out;
    }

    // protos32.py "imports": a __cdecl import's stack arguments as its callers clean them up (thunk
    // or IAT slot -> words). An import Ghidra has no prototype for is given that many; one with a
    // signature of its own (a type library's, IMPORTED, or a hand-set one) keeps it. The /MD
    // CRT's `_crt_atexit()` lost its function so, and ucrt called garbage at exit (2026-10-24)
    // vcruntime's x86 C++ frame handlers take the frame's FuncInfo in eax, then the four arguments
    // every exception handler is called with. Typed so, a handler thunk's `mov eax, FuncInfo; jmp
    // __CxxFrameHandler3` passes its FuncInfo; without, the decompiler dropped it (rhtest eh)
    private void applyEhHandlerImports() throws Exception {
        int set = 0;
        DataType u4 = Undefined.getUndefinedDataType(4);
        for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
            String n = f.getName().replaceFirst("^_+", "");
            if (!n.matches("CxxFrameHandler[23]?") || f.getSignatureSource() == SourceType.USER_DEFINED) continue;
            if (f.hasCustomVariableStorage() && f.getParameterCount() == 5) continue;
            List<Variable> params = new ArrayList<>();
            params.add(new ParameterImpl("funcinfo", u4, new ghidra.program.model.listing.VariableStorage(
                    currentProgram, currentProgram.getRegister("EAX")), currentProgram));
            for (int i = 0; i < 4; i++)
                params.add(new ParameterImpl("param_" + (i + 1), u4,
                        new ghidra.program.model.listing.VariableStorage(currentProgram, 4 + 4 * i, 4), currentProgram));
            Variable ret = new ghidra.program.model.listing.ReturnParameterImpl(u4,
                    new ghidra.program.model.listing.VariableStorage(currentProgram, currentProgram.getRegister("EAX")),
                    currentProgram);
            f.updateFunction("__cdecl", ret, params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
            set++;
        }
        println("ApplyFacts: C++ frame handler imports given their FuncInfo in eax " + set);
    }

    // The x86 CRT's SSE2 math, `_libm_sse2_sin_precise` and the rest (api-ms-win-crt-math, what
    // /arch:SSE2 calls for sin, cos, exp, log, pow ...): a convention of their own, the double in
    // xmm0 (pow's and atan2's second in xmm1) and the result in xmm0. Untyped, the call took no
    // argument and returned nothing, and the decompiler went on with xmm0 as before the call, the
    // argument read as sin's result (rhtest fpenv-O2's trig, then the translation's call through
    // an adapter with nothing to pass, a fault)
    private void applyLibmSse2_32() throws Exception {
        int set = 0;
        DataType d = ghidra.program.model.data.DoubleDataType.dataType;
        for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
            String n = f.getName().replaceFirst("^_+", "");
            if (!n.startsWith("libm_sse2_")) continue;
            String op = n.substring("libm_sse2_".length()).replaceFirst("_precise$", "");
            int args = op.equals("pow") || op.equals("atan2") ? 2 : 1;
            List<Variable> params = new ArrayList<>();
            for (int i = 0; i < args; i++) {
                params.add(new ParameterImpl("x" + i, d, new ghidra.program.model.listing.VariableStorage(
                        currentProgram, currentProgram.getRegister("XMM" + i + "_Qa")), currentProgram));
            }
            Variable ret = new ghidra.program.model.listing.ReturnParameterImpl(d, new ghidra.program.model.listing.VariableStorage(
                    currentProgram, currentProgram.getRegister("XMM0_Qa")), currentProgram);
            f.updateFunction("__cdecl", ret, params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
            set++;
        }
        println("ApplyFacts: the CRT's SSE2 math imports typed " + set);
    }

    private void applyImportArgs32(JsonObject imports) throws Exception {
        int set = 0, kept = 0, missing = 0;
        DataType u4 = Undefined.getUndefinedDataType(4);
        for (Map.Entry<String, JsonElement> e : imports.entrySet()) {
            Address a = addr(e.getKey());
            Function f = getFunctionAt(a);
            if (f != null && f.isThunk()) {
                f = f.getThunkedFunction(true);
            } else if (f == null) {
                // (an IAT slot: the external function it refers to)
                Reference r = currentProgram.getReferenceManager().getPrimaryReferenceFrom(a, 0);
                f = r != null && r.isExternalReference() ? getFunctionAt(r.getToAddress()) : null;
            }
            if (f == null) {
                missing++;
                continue;
            }
            int n = e.getValue().getAsInt();
            SourceType src = f.getSignatureSource();
            if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED || f.getParameterCount() >= n) {
                // (one an earlier run gave its arguments: its eax result too, below)
                if (src == SourceType.ANALYSIS && f.getReturnType() instanceof ghidra.program.model.data.VoidDataType)
                    f.setReturnType(u4, SourceType.ANALYSIS);
                kept++;
                continue;
            }
            List<Variable> params = new ArrayList<>();
            for (int i = 0; i < n; i++) params.add(new ParameterImpl("param_" + (i + 1), u4, currentProgram));
            // (and eax as its result, where it has none: void, the CRT's printf wrapper returned 0
            // for __stdio_common_vfprintf's count, rhtest crt-O2 2026-10-24)
            DataType rt = f.getReturnType();
            Variable ret = rt == null || rt instanceof ghidra.program.model.data.VoidDataType
                    ? new ghidra.program.model.listing.ReturnParameterImpl(u4, currentProgram) : null;
            f.updateFunction("__cdecl", ret, params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.ANALYSIS);
            set++;
        }
        println("ApplyFacts: import arguments set " + set + ", kept " + kept + " (a signature of their own), no function "
                + missing);
    }

    // structs.json: {"structs": {name: {"size": n, "fields": [[name, offset, type], ...]}}}. A type
    // a library match named but Ghidra never laid out is an empty placeholder of one byte (the
    // CRT's _LocaleUpdate, _Lockit: `local_14.localeinfo` then had no field, and every function
    // using one was a stub, 2026-10-23). Each is laid out in place, where the placeholder is (or
    // made, if none), its fields' types by name: a built-in, a type the program has, `T *`, `T[n]`.
    private void applyStructs(JsonObject root) throws Exception {
        ghidra.program.model.data.DataTypeManager dtm = currentProgram.getDataTypeManager();
        int laid = 0, failed = 0;
        JsonObject structs = root.getAsJsonObject("structs");
        // (all named first, so a field can be of another one of them)
        Map<String, ghidra.program.model.data.Structure> made = new HashMap<>();
        for (String name : structs.keySet()) {
            ghidra.program.model.data.Structure s = null;
            List<DataType> found = new ArrayList<>();
            dtm.findDataTypes(name, found);
            for (DataType d : found) if (d instanceof ghidra.program.model.data.Structure ss) s = ss;
            if (s == null) {
                s = (ghidra.program.model.data.Structure) dtm.addDataType(
                        new ghidra.program.model.data.StructureDataType(name, 0), null);
            }
            made.put(name, s);
        }
        for (Map.Entry<String, JsonElement> e : structs.entrySet()) {
            JsonObject o = e.getValue().getAsJsonObject();
            ghidra.program.model.data.Structure s = made.get(e.getKey());
            try {
                s.deleteAll();
                s.growStructure(o.get("size").getAsInt());
                for (JsonElement fe : o.getAsJsonArray("fields")) {
                    JsonArray f = fe.getAsJsonArray();
                    DataType t = structType(f.get(2).getAsString(), dtm, made);
                    s.replaceAtOffset(f.get(1).getAsInt(), t, t.getLength(), f.get(0).getAsString(), null);
                }
                laid++;
            } catch (Exception ex) {
                if (failed++ < 5) printerr("ApplyFacts: struct " + e.getKey() + ": " + ex);
            }
        }
        println("ApplyFacts: structures laid out " + laid + ", failed " + failed);
    }

    private DataType structType(String t, ghidra.program.model.data.DataTypeManager dtm,
                                Map<String, ghidra.program.model.data.Structure> made) throws Exception {
        t = t.trim();
        java.util.regex.Matcher arr = java.util.regex.Pattern.compile("(.+)\\[(\\d+)\\]").matcher(t);
        if (arr.matches()) {
            DataType el = structType(arr.group(1), dtm, made);
            return new ArrayDataType(el, Integer.parseInt(arr.group(2)), el.getLength());
        }
        if (t.endsWith("*")) {
            return new ghidra.program.model.data.PointerDataType(structType(t.substring(0, t.length() - 1), dtm, made),
                    currentProgram.getDefaultPointerSize());
        }
        switch (t) {
            case "int": return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint": return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "short": return ghidra.program.model.data.ShortDataType.dataType;
            case "ushort": return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "char": return ghidra.program.model.data.CharDataType.dataType;
            case "byte": return ghidra.program.model.data.ByteDataType.dataType;
            case "bool": return ghidra.program.model.data.BooleanDataType.dataType;
            case "void": return ghidra.program.model.data.VoidDataType.dataType;
            case "wchar_t": return ghidra.program.model.data.WideCharDataType.dataType;
            default:
                if (made.containsKey(t)) return made.get(t);
                List<DataType> found = new ArrayList<>();
                dtm.findDataTypes(t, found);
                if (!found.isEmpty()) return found.get(0);
                throw new IllegalArgumentException("no type " + t);
        }
    }

    // Two of Ghidra's own mistakes on this binary. Functions at addresses that read as UTF-16 text
    // (0x0063005f: "_\0c\0"), which its analysis took from wide strings for code pointers and which
    // nothing calls, jumps to or points to: removed (175, junk decoded from the middle of other
    // code). And bodies cut short after their first instruction (FUN_006c74f0 is `push ebx` alone,
    // its code running on into bytes no function has): their body flowed again.
    // two printable UTF-16 characters as a 32-bit word: 0x00XX00YY
    private static boolean texty(long a) {
        int b0 = (int) (a & 0xff), b1 = (int) ((a >> 8) & 0xff), b2 = (int) ((a >> 16) & 0xff), b3 = (int) ((a >> 24) & 0xff);
        return b1 == 0 && b3 == 0 && b0 >= 0x20 && b0 < 0x7f && b2 >= 0x20 && b2 < 0x7f;
    }

    // a reference from inside wide text: not code, and the words before and after it text too
    private boolean fromText(Address from) {
        try {
            if (getInstructionContaining(from) != null) return false;
            return texty(getInt(from.subtract(4)) & 0xffffffffL) && texty(getInt(from.add(4)) & 0xffffffffL);
        } catch (Exception e) {
            return false;
        }
    }

    private void cleanFunctions32() throws Exception {
        int removed = 0, regrown = 0;
        List<Function> junk = new ArrayList<>(), shortened = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            long a = f.getEntryPoint().getOffset();
            // (referenced only from inside wide text, the string's own characters read as a pointer
            // to it: the words either side of the reference text too. vtables.py took a table of
            // wide strings for vtables, ApplyFacts typed their "slots" as pointers, and the junk at
            // 0x4d0050 and 0x4d0052 kept those references and cut 0x4cffd0 short, a VS2010 client)
            boolean refd = false;
            for (ghidra.program.model.symbol.Reference r : getReferencesTo(f.getEntryPoint())) {
                if (!fromText(r.getFromAddress())) { refd = true; break; }
            }
            if (texty(a) && !refd
                    && f.getSignatureSource() != SourceType.USER_DEFINED && f.getSymbol().getSource() != SourceType.USER_DEFINED) {
                junk.add(f);
            }
        }
        for (Function f : junk) {
            if (currentProgram.getFunctionManager().removeFunction(f.getEntryPoint())) removed++;
        }
        // (and a DEFAULT-named function at a jump target inside the function before it, nothing
        // else reaching it: no call, no pointer, only that function's own jumps. Its parent's body
        // ended at it, and what the parent did past it went without the parent's facts: a UI
        // reset 0x594d90 lost its loop to FUN_00594da8 (the `je` past its early `ret 4`), the
        // loop's `call [eax + 8]` went out with no `this`, and a mouse-over called 0xcccccccc.
        // jumppieces.py lists them, 21 on a client, 2026-10-28)
        List<Function[]> pieces = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk() || f.getSymbol().getSource() != SourceType.DEFAULT) continue;
            Function prev = getFunctionBefore(f.getEntryPoint());   // (FlatProgramAPI's)
            if (prev == null || prev.isThunk()) continue;
            boolean onlyPrevJumps = false;
            for (ghidra.program.model.symbol.Reference r : getReferencesTo(f.getEntryPoint())) {
                Function from = getFunctionContaining(r.getFromAddress());
                if (!r.getReferenceType().isJump() || from == null || !from.equals(prev)) {
                    onlyPrevJumps = false;
                    break;
                }
                onlyPrevJumps = true;
            }
            if (onlyPrevJumps) pieces.add(new Function[] {f, prev});
        }
        int merged = 0;
        for (Function[] fp : pieces) {
            if (currentProgram.getFunctionManager().removeFunction(fp[0].getEntryPoint())) {
                CreateFunctionCmd.fixupFunctionBody(currentProgram, fp[1], monitor);
                merged++;
            }
        }
        println("ApplyFacts: functions at a jump target of the function before them merged into it " + merged);
        // (the bodies cut short, looked for once the junk is gone: a function ending where a junk
        // one began runs on now)
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            Instruction last = getInstructionContaining(f.getBody().getMaxAddress());
            if (last != null && last.getFallThrough() != null && !last.getFlowType().isCall()
                    && getFunctionContaining(last.getFallThrough()) == null && getInstructionAt(last.getFallThrough()) != null) {
                shortened.add(f);
            }
        }
        for (Function f : shortened) {
            CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
            regrown++;
        }
        println("ApplyFacts: junk functions at text addresses removed " + removed + ", cut-short bodies regrown " + regrown);
    }

    // x86 keep conventions: a base one (__cdecl, __stdcall, __thiscall, __fastcall) with the volatile
    // registers a function leaves as it found them unaffected (protos32.py "keep"). /LTCG lets a
    // caller keep a value in ecx or edx across a call to one; under the base convention the
    // decompiler takes the call to kill them and names what follows `extraout_ECX`. Each is the
    // base's own prototype from the language's x86win.cspec, renamed, the kept registers moved from
    // killedbycall and likelytrash into unaffected (eax too: then no output is killed by the call)
    // the convention a keep one is made from: a custom function's is the base its storage was set
    // under (__stdcall where it pops stack arguments), protos32.py giving a register convention
    // that keeps some its registers by name (__security_check_cookie, 2026-10-24)
    private static String keepBase32(JsonObject o) {
        String cc = o.get("cc").getAsString();
        if (!cc.equals("custom")) return cc;
        return o.get("callee_cleans").getAsBoolean() && o.get("stack").getAsInt() > 0 ? "__stdcall" : "__cdecl";
    }

    private static String keepName32(String cc, JsonArray regs) {
        StringBuilder n = new StringBuilder(cc).append("_keep");
        for (JsonElement r : regs) n.append('_').append(r.getAsString());
        return n.toString();
    }

    private static String withoutIn(String x, String section, String reg) {
        int a = x.indexOf("<" + section + ">");
        int b = a < 0 ? -1 : x.indexOf("</" + section + ">", a);
        if (b < 0) return x;
        String inner = x.substring(a, b).replaceAll("<register name=\"" + reg + "\"/>\\s*", "");
        return x.substring(0, a) + inner + x.substring(b);
    }

    private void addKeepConventions32(java.util.Set<String> names) throws Exception {
        String cspec = new String(java.nio.file.Files.readAllBytes(ghidra.framework.Application
                .getModuleDataFile("x86", "languages/x86win.cspec").getFile(false).toPath()));
        Class<?> se = Function.class.getClassLoader().loadClass("ghidra.program.database.SpecExtension");
        Object ext = se.getConstructor(ghidra.program.model.listing.Program.class).newInstance(currentProgram);
        java.lang.reflect.Method add = se.getMethod("addReplaceCompilerSpecExtension", String.class,
                ghidra.util.task.TaskMonitor.class);
        int made = 0;
        for (String name : names) {
            String base = name.substring(0, name.indexOf("_keep"));
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                    "<prototype name=\"" + java.util.regex.Pattern.quote(base) + "\".*?</prototype>",
                    java.util.regex.Pattern.DOTALL).matcher(cspec);
            if (!m.find()) {
                printerr("ApplyFacts: no " + base + " in x86win.cspec for " + name);
                continue;
            }
            String x = m.group().replaceFirst("name=\"" + java.util.regex.Pattern.quote(base) + "\"", "name=\"" + name + "\"");
            StringBuilder unaff = new StringBuilder();
            for (String r : name.substring(name.indexOf("_keep") + 5).split("_")) {
                if (r.isEmpty()) continue;
                String reg = r.toUpperCase();
                // (out of killedbycall and likelytrash, into unaffected: inside each section only,
                // __thiscall's input names ECX too)
                x = withoutIn(x, "killedbycall", reg);
                x = withoutIn(x, "likelytrash", reg);
                unaff.append("<register name=\"").append(reg).append("\"/>");
                if (reg.equals("EAX")) x = x.replace("<output killedbycall=\"true\">", "<output>");
            }
            x = x.replaceFirst("</unaffected>", unaff + "</unaffected>");
            x = x.replaceAll("<killedbycall>\\s*</killedbycall>", "").replaceAll("<likelytrash>\\s*</likelytrash>", "");
            add.invoke(ext, x, monitor);
            made++;
        }
        println("ApplyFacts: x86 keep conventions made " + made + " of " + names.size());
    }

    // A return its callers read (protos32.py "ret": al/ax/eax "i1"/"i2"/"i4", edx:eax "i8", st0 "f4"/"d8"):
    // Ghidra's type where it is one of that width and kind, else one that is. Ghidra had left
    // the allocator FUN_004067a0 void, and its callers' use of eax was lost
    private int returnsSet = 0;
    private void setReturn32(Function f, String kind) throws Exception {
        DataType have = f.getReturnType();
        // (void, protos32.py "v": a result only inferred for one with a path that never writes
        // eax, refused there; an earlier round's type goes. _free's uint stayed in the project, and
        // ___free_lconv_num, ending in its calls, a stub of extraout_EAX, rhtest msvc-16.00-x86)
        if (kind.equals("v")) {
            if (have instanceof ghidra.program.model.data.VoidDataType) return;
            if (f.hasCustomVariableStorage()) {
                f.setReturn(ghidra.program.model.data.VoidDataType.dataType,
                        ghidra.program.model.listing.VariableStorage.VOID_STORAGE, SourceType.ANALYSIS);
            } else {
                f.setReturnType(ghidra.program.model.data.VoidDataType.dataType, SourceType.ANALYSIS);
            }
            returnsSet++;
            return;
        }
        // (a float or double in xmm0, /LTCG's own convention between functions it sees whole: its
        // storage named, as no x86 model returns there. Left to the model, the caller read the
        // value from before the call, rhtest calls-GL fc_dbl, 2026-10-24)
        if (kind.equals("s4") || kind.equals("q8")) {
            boolean q = kind.equals("q8");
            DataType want = q ? ghidra.program.model.data.DoubleDataType.dataType
                    : ghidra.program.model.data.FloatDataType.dataType;
            if (want.isEquivalent(have) && f.hasCustomVariableStorage()
                    && f.getReturn().getVariableStorage().getRegister() != null
                    && f.getReturn().getVariableStorage().getRegister().getName().startsWith("XMM0")) return;
            if (!f.hasCustomVariableStorage()) f.setCustomVariableStorage(true);
            f.setReturn(want, new ghidra.program.model.listing.VariableStorage(currentProgram,
                    currentProgram.getRegister(q ? "XMM0_Qa" : "XMM0_Da")), SourceType.ANALYSIS);
            returnsSet++;
            return;
        }
        // (an int in ecx, protos32.py's "c4": a function's code its own funclet hands a value to in
        // ecx, seh's __finally body and the code after it, rhtest eh-O2)
        // (and one in a callee-saved register a frame funclet hands back, "si4" / "di4" / "bx4":
        // __updatetlocinfo's __finally, `mov esi, [ebp - 0x1c]; ret`, its caller's result)
        String retReg = kind.equals("c4") ? "ECX" : kind.equals("si4") ? "ESI" : kind.equals("di4") ? "EDI"
                : kind.equals("bx4") ? "EBX" : null;
        if (retReg != null) {
            DataType want = ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            if (want.isEquivalent(have) && f.hasCustomVariableStorage()
                    && f.getReturn().getVariableStorage().getRegister() != null
                    && f.getReturn().getVariableStorage().getRegister().getName().equals(retReg)) return;
            if (!f.hasCustomVariableStorage()) f.setCustomVariableStorage(true);
            f.setReturn(want, new ghidra.program.model.listing.VariableStorage(currentProgram,
                    currentProgram.getRegister(retReg)), SourceType.ANALYSIS);
            returnsSet++;
            return;
        }
        boolean haveFloat = have instanceof ghidra.program.model.data.AbstractFloatDataType;
        boolean usable = have != null && !Undefined.isUndefined(have)
                && !(have instanceof ghidra.program.model.data.VoidDataType);
        DataType want;
        switch (kind) {
            case "i8":
                want = usable && !haveFloat && have.getLength() == 8 ? have
                        : ghidra.program.model.data.UnsignedLongLongDataType.dataType;
                break;
            case "f4":
                want = ghidra.program.model.data.FloatDataType.dataType;
                break;
            case "d8":
                want = ghidra.program.model.data.DoubleDataType.dataType;
                break;
            case "i1":
                want = usable && !haveFloat && have.getLength() == 1 ? have
                        : ghidra.program.model.data.ByteDataType.dataType;
                break;
            case "i2":
                want = usable && !haveFloat && have.getLength() == 2 ? have
                        : ghidra.program.model.data.UnsignedShortDataType.dataType;
                break;
            default:
                want = usable && !haveFloat && have.getLength() == 4 ? have
                        : ghidra.program.model.data.UnsignedIntegerDataType.dataType;
        }
        // (custom storage: the type right is not enough, its storage must be the register too. One
        // void before has none, and an int with none returns nothing: VS2010's _cftoe2_l, its eax
        // result `extraout_EAX` in _cftog_l, a stub on printf's %g, rhtest msvc-16.00-x86 crt)
        boolean storageOff = false;
        if (want == have && f.hasCustomVariableStorage() && !(want instanceof ghidra.program.model.data.AbstractFloatDataType)) {
            ghidra.program.model.lang.Register r = f.getReturn().getVariableStorage().getRegister();
            int n = want.getLength();
            String rn = n > 4 ? "EAX" : n == 1 ? "AL" : n == 2 ? "AX" : "EAX";
            storageOff = n > 4 ? f.getReturn().getVariableStorage().getVarnodeCount() != 2
                    : r == null || !r.getName().equals(rn);
        }
        if (want != have || storageOff) {
            if (f.hasCustomVariableStorage()) {
                // (custom storage: the return's own too, or "Storage can't be resized: <VOID>")
                // (an integer one only: a float in st0's 10 bytes is left as it is, the port's
                // float10 a double. edx:eax is the pair, high first: left to the decompiler, a
                // double's bits returned there were typed double, and dbits' callers converted the
                // value, -7.0 as -7, once a double parameter made the storage custom, rhtest
                // float-Od 2026-10-24)
                // A float in st0 the same: its 10 bytes as float10 (the register's size; the port's
                // float10 is a double). Left alone, a fresh import's dmin and fsqrt returned nothing
                int n = want.getLength();
                if (want instanceof ghidra.program.model.data.AbstractFloatDataType) {
                    DataType f10 = ghidra.program.model.data.Float10DataType.dataType;
                    if (!f10.isEquivalent(have)) {
                        f.setReturn(f10, new ghidra.program.model.listing.VariableStorage(currentProgram,
                                currentProgram.getRegister("ST0")), SourceType.ANALYSIS);
                        returnsSet++;
                    }
                    return;
                }
                ghidra.program.model.listing.VariableStorage vs = n > 4
                        ? new ghidra.program.model.listing.VariableStorage(currentProgram,
                                currentProgram.getRegister("EDX"), currentProgram.getRegister("EAX"))
                        : new ghidra.program.model.listing.VariableStorage(currentProgram,
                                currentProgram.getRegister(n == 1 ? "AL" : n == 2 ? "AX" : "EAX"));
                f.setReturn(want, vs, SourceType.ANALYSIS);
            } else {
                f.setReturnType(want, SourceType.ANALYSIS);
            }
            returnsSet++;
        }
    }

    private Address addr(String hex) {
        return toAddr(Long.parseUnsignedLong(hex.startsWith("0x") ? hex.substring(2) : hex, 16));
    }

    // the piece and interior addresses (applyPieces): never a function of their own
    private final java.util.Set<Address> partOfAnother = new java.util.HashSet<>();

    private Function functionAt(Address a) {
        Function f = getFunctionAt(a);
        if (f == null && !partOfAnother.contains(a)) {
            CreateFunctionCmd cmd = new CreateFunctionCmd(a);
            if (cmd.applyTo(currentProgram, monitor)) {
                created++;
                f = getFunctionAt(a);
            }
        }
        return f;
    }

    private Namespace namespace(String path) throws Exception {
        Namespace ns = currentProgram.getGlobalNamespace();
        for (String part : path.split("::")) {
            Namespace next = symbols.getNamespace(part, ns);
            ns = next != null ? next : symbols.createNameSpace(ns, part, SourceType.IMPORTED);
        }
        return ns;
    }

    private void name(Function f, String ns, String name) throws Exception {
        if (f.getSymbol().getSource() == SourceType.USER_DEFINED) {
            kept++;
            return;
        }
        Namespace space = namespace(ns);
        // a name another function already has in the namespace gets this one's address: five
        // script object types each register their own CreateAnimationGroup, and with one name
        // between them a call in the decompiled text no longer says which function it calls (the
        // translator left 125 such Lua:: calls unresolved, C2065 'Lua', 2026-10-16)
        for (Symbol s : symbols.getSymbols(name, space)) {
            if (s.getObject() instanceof Function && !s.getAddress().equals(f.getEntryPoint())) {
                name = name + "_" + f.getEntryPoint().toString();
                break;
            }
        }
        f.setParentNamespace(space);
        f.setName(name, SourceType.IMPORTED);
        named++;
    }

    // protos.json "stack_blocks" (tools/protos.py): the stack blocks a function moves 16 bytes at a
    // time. Where the decompiler split one into two or more narrower locals, they become one byte
    // array of the block's size: split, a 32-byte copy out of a 4-byte `local_4e8` was dropped as
    // dead, and Ed25519's verify (FUN_1420bf4f0) compared R with a buffer never written (2026-10-20).
    // (grow: x86's object blocks (protos32.py local_block) take in a variable that straddles them,
    // the analysis's own guess at the object's pieces, rather than give up on it)
    private void applyStackBlocks(JsonObject blocks, boolean grow) throws Exception {
        int made = 0, functions = 0, skipped = 0, failed = 0, cleared = 0;
        String firstError = null;
        // (a block an earlier round made that the facts no longer give: gone. The project keeps
        // them, and a too-wide rule's `byte [8]` stayed a LARGE_INTEGER's return, 2026-10-24)
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            ghidra.program.model.listing.StackFrame sf = f.getStackFrame();
            JsonElement want = blocks.get(String.format("0x%x", f.getEntryPoint().getOffset()));
            for (Variable v : sf.getStackVariables()) {
                if (!v.getName().startsWith("blk_")) continue;
                boolean kept = false;
                if (want != null) {
                    for (JsonElement b : want.getAsJsonArray()) {
                        int off = b.getAsJsonArray().get(0).getAsInt();
                        int size = b.getAsJsonArray().get(1).getAsInt();
                        kept |= v.getStackOffset() <= off && v.getStackOffset() + v.getLength() >= off + size;
                    }
                }
                if (!kept) {
                    sf.clearVariable(v.getStackOffset());
                    cleared++;
                }
            }
        }
        if (cleared > 0) println("ApplyFacts: stack blocks the facts no longer give cleared " + cleared);
        for (Map.Entry<String, JsonElement> e : blocks.entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) continue;
            ghidra.program.model.listing.StackFrame sf = f.getStackFrame();
            boolean touched = false;
            for (JsonElement b : e.getValue().getAsJsonArray()) {
                int off = b.getAsJsonArray().get(0).getAsInt();
                int size = b.getAsJsonArray().get(1).getAsInt();
                for (boolean grew = grow; grew; ) {
                    grew = false;
                    for (Variable v : sf.getStackVariables()) {
                        int vo = v.getStackOffset(), ve = vo + Math.max(1, v.getLength());
                        if (ve <= off || vo >= off + size || vo >= 0) continue;
                        if (vo < off) { size += off - vo; off = vo; grew = true; }
                        if (ve > off + size) { size = ve - off; grew = true; }
                    }
                }
                List<Variable> inside = new ArrayList<>();
                boolean straddles = false;
                for (Variable v : sf.getStackVariables()) {
                    int vo = v.getStackOffset(), ve = vo + Math.max(1, v.getLength());
                    if (ve <= off || vo >= off + size) continue;
                    if (vo < off || ve > off + size) straddles = true;
                    inside.add(v);
                }
                // (none that a wider variable straddles, nor one a single variable already covers
                // whole; the decompiler's own split locals are not in the listing, so an empty
                // slot is the usual case)
                if (straddles || (inside.size() == 1 && inside.get(0).getStackOffset() == off
                        && inside.get(0).getLength() >= size)) {
                    if (skipped++ == 0 && firstError == null) {
                        StringBuilder sb = new StringBuilder(f.getEntryPoint() + " [" + off + "," + size + "] has");
                        for (Variable v : inside) sb.append(" " + v.getName() + "@" + v.getStackOffset() + ":" + v.getLength());
                        firstError = sb.toString();
                    }
                    continue;
                }
                for (Variable v : inside) sf.clearVariable(v.getStackOffset());
                try {
                    // (an object's block as bytes: undefined ones are no locked type, and the
                    // decompiler laid the frame out again without it, the stores as dead as before)
                    sf.createVariable(String.format("blk_%x", -off), off,
                            new ArrayDataType(grow ? ghidra.program.model.data.ByteDataType.dataType
                                    : Undefined.getUndefinedDataType(1), size, 1), SourceType.USER_DEFINED);
                    made++;
                    touched = true;
                } catch (Exception ex) {
                    // (a parameter's slot, or another conflict: leave it)
                    if (failed++ == 0) firstError = f.getEntryPoint() + " " + off + ": " + ex;
                }
            }
            if (touched) functions++;
        }
        println("ApplyFacts: split stack blocks made arrays " + made + " in " + functions + " functions"
                + " (skipped " + skipped + ", failed " + failed + (firstError != null ? ", first: " + firstError : "") + ")");
    }

    private void applyLua(JsonObject root) throws Exception {
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = functionAt(addr(e.getKey()));
            if (f == null) continue;
            String full = e.getValue().getAsString();   // "Inventory.GetItemName" or "GetName"
            int dot = full.lastIndexOf('.');
            String ns = dot < 0 ? "Lua" : "Lua::" + full.substring(0, dot);
            name(f, ns, dot < 0 ? full : full.substring(dot + 1));
        }
    }

    // An address inside an instruction that starts before it: no function's entry.
    private boolean midInstruction(Address a) {
        Instruction in = getInstructionContaining(a);
        return in != null && !in.getAddress().equals(a);
    }

    private void applyVtables(JsonObject root) throws Exception {
        int skipped = 0;
        for (JsonElement el : root.getAsJsonArray("vtables")) {
            JsonObject v = el.getAsJsonObject();
            Address a = addr(v.get("vtable").getAsString());
            int slots = v.getAsJsonArray("slots").size();
            // (not a table one of whose slots lands inside an instruction: data that only looks
            // like code pointers, UTF-16 text among it (0x00650065). A function made there took a
            // byte out of the one around it, and FUN_009f9f40, split inside its `push 0x268`, was
            // read only up to it: a save it pops later looked like an argument, and the esi read
            // as its input made its caller a stub, a VS2010 client 2026-10-25)
            boolean bogus = false;
            for (JsonElement s : v.getAsJsonArray("slots")) {
                if (midInstruction(addr(s.getAsString()))) {
                    bogus = true;
                    break;
                }
            }
            if (bogus) {
                skipped++;
                continue;
            }
            String label = "vtable_" + a.toString();
            Symbol existing = getSymbolAt(a);
            // (a name Ghidra's RTTI analysis gave, `Client::UI::AddonX::vftable` on a binary built
            // with RTTI, says more than vtable_<address>: kept)
            if (existing == null || existing.getSource() == SourceType.DEFAULT
                    || (existing.getSource() == SourceType.ANALYSIS && !existing.getName().endsWith("vftable"))) {
                createLabel(a, label, true, SourceType.IMPORTED);
                labelled++;
            }
            if (slots > 0) {
                int ptr = currentProgram.getDefaultPointerSize();
                try {
                    clearListing(a, a.add((long) ptr * slots - 1));
                    createData(a, new ArrayDataType(PointerDataType.dataType, slots, ptr));
                } catch (Exception ex) {
                    // leave whatever analysis put there
                }
                for (JsonElement s : v.getAsJsonArray("slots")) functionAt(addr(s.getAsString()));
            }
            StringBuilder sb = new StringBuilder("vtable, " + slots + " slots; loaded by");
            for (JsonElement r : v.getAsJsonArray("referenced_by")) sb.append(' ').append(r.getAsString());
            setPlateComment(a, sb.toString());
        }
        if (skipped > 0) println("ApplyFacts: " + skipped + " vtables skipped, a slot inside an instruction");
    }

    // What earlier runs' tables of that kind did: a function whose entry is inside another's
    // instruction goes, and a body cut inside an instruction is found again from its entry.
    private void repairBodies() throws Exception {
        List<Function> mid = new ArrayList<>();
        List<Function> cut = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            if (midInstruction(f.getEntryPoint())) {
                mid.add(f);
                continue;
            }
            for (ghidra.program.model.address.AddressRange r : f.getBody()) {
                Instruction in = getInstructionContaining(r.getMaxAddress());
                if (in != null && in.getMaxAddress().compareTo(r.getMaxAddress()) > 0) {
                    cut.add(f);
                    break;
                }
            }
        }
        for (Function f : mid) currentProgram.getFunctionManager().removeFunction(f.getEntryPoint());
        int fixed = 0;
        for (Function f : cut) {
            if (CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor)) fixed++;
        }
        println(String.format("ApplyFacts: removed %d functions inside an instruction, refit %d of %d bodies cut inside one",
                mid.size(), fixed, cut.size()));
    }

    // The Windows API prototypes Ghidra ships (Base/data/typeinfo/win32), by function name. The
    // definitions read through the archive, so it stays open until they are resolved.
    private Map<String, FunctionDefinition> windowsPrototypes(FileDataTypeManager archive) {
        Map<String, FunctionDefinition> out = new HashMap<>();
        Iterator<DataType> it = archive.getAllDataTypes();
        while (it.hasNext()) {
            DataType t = it.next();
            if (t instanceof FunctionDefinition) {
                out.putIfAbsent(t.getName(), (FunctionDefinition) t);
            }
        }
        return out;
    }

    // Import slots recovered from a live process by tools/iat_dump.py: label each slot
    // with its API name and type it as a pointer to the API's prototype, so `call [slot]`
    // reads as the API with its arguments. A bare pointer let the decompiler call
    // EnterCriticalSection with none (FUN_1415ae990: the bgs mutex lock, 2026-10-15).
    private void applyImports(JsonObject root) throws Exception {
        File gdt = Application.getModuleDataFile("Base", "typeinfo/win32/windows_vs12_64.gdt").getFile(false);
        FileDataTypeManager archive = FileDataTypeManager.openFileArchive(gdt, false);
        try {
            applyImports(root, windowsPrototypes(archive));
        } finally {
            archive.close();
        }
    }

    private void applyImports(JsonObject root, Map<String, FunctionDefinition> prototypes) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int typed = 0, untyped = 0;
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("imports").entrySet()) {
            JsonObject i = e.getValue().getAsJsonObject();
            JsonElement n = i.get("imported_name");
            if (n == null || n.isJsonNull()) continue;
            // a list means folded identical code (htons/ntohs): keep every candidate
            String name;
            if (n.isJsonArray()) {
                StringBuilder sb = new StringBuilder();
                for (JsonElement x : n.getAsJsonArray()) {
                    if (sb.length() > 0) sb.append("_or_");
                    sb.append(x.getAsString());
                }
                name = sb.toString();
            } else {
                name = n.getAsString();
            }
            Address a = addr(e.getKey());
            String dll = i.get("dll").getAsString().toUpperCase();
            // folded identical code (htons_or_ntohs): the candidates share a prototype
            FunctionDefinition proto = prototypes.get(name.split("_or_")[0]);
            DataType slot = proto == null ? PointerDataType.dataType
                    : new PointerDataType(dtm.resolve(proto, DataTypeConflictHandler.DEFAULT_HANDLER), 8);
            try {
                clearListing(a, a.add(7));
                createData(a, slot);
                if (proto != null) typed++; else untyped++;
            } catch (Exception ex) {
                // keep analysis' typing
            }
            Symbol existing = getSymbolAt(a);
            if (existing != null && existing.getSource() == SourceType.USER_DEFINED) {
                kept++;
                continue;
            }
            createLabel(a, name, namespace("Import::" + dll.replace('.', '_')),
                    true, SourceType.IMPORTED);
            named++;
        }
        println("ApplyFacts: import slots typed with a Windows prototype " + typed + ", bare pointers " + untyped);
    }

    // funcptrs.json (tools/funcptrs.py): data slots holding a function's address that code calls
    // through. Typed as a pointer to the target's own signature, as the import slots are, so the
    // decompiler stops guessing each call's arguments from the registers it sees set: as a bare
    // pointer, curl's Curl_ccalloc slot (0x142d3e8b8 -> _calloc_base) came out as `(1)` with the
    // size dropped at about half of its calls (Curl_multi_handle, 2026-10-15).
    private void applyFuncptrs(JsonObject root) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int typed = 0, unsigned = 0, occupied = 0;
        for (Map.Entry<String, JsonElement> e : root.entrySet()) {
            Address a = addr(e.getKey());
            Function f = getFunctionAt(addr(e.getValue().getAsJsonObject().get("target").getAsString()));
            if (f == null || f.getSignatureSource() == SourceType.DEFAULT) {
                // no signature to give it: an empty one would drop every argument
                unsigned++;
                continue;
            }
            Data d = getDataAt(a);
            if (d != null && d.isDefined() && !(d.getDataType() instanceof Pointer)
                    && !(d.getDataType() instanceof Undefined)) {
                // a struct or array someone typed: leave it
                occupied++;
                continue;
            }
            FunctionDefinitionDataType sig = new FunctionDefinitionDataType(f, true);
            sig.setName("fp_" + f.getName());
            DataType slot = new PointerDataType(dtm.resolve(sig, DataTypeConflictHandler.REPLACE_HANDLER), 8);
            try {
                clearListing(a, a.add(7));
                createData(a, slot);
                typed++;
            } catch (Exception ex) {
                occupied++;
            }
        }
        println(String.format("ApplyFacts: function-pointer slots typed %d, target without a signature %d, " +
                "left as typed %d", typed, unsigned, occupied));
    }

    // 32-bit: a call through a data slot that holds a function's entry and that nothing writes,
    // `call [0x12b57bc]` (the image's own table of CRT routines, not an import's): a call override
    // to that function, which the decompiler takes for a direct call with the callee's own
    // prototype and storage. Called through the pointer, a math routine's x87 result was lost
    // (extraout_ST0), and an XAPO's format check a stub, 2026-10-26. (A pointer type on the slot
    // was not enough: a function definition carries no custom storage, its st0 result.)
    private final java.util.Set<Address> constSlotCalls = new java.util.HashSet<>();

    private void overrideCall(ReferenceManager refs, Instruction ins, Function target) {
        Address from = ins.getAddress();
        for (Reference r : refs.getReferencesFrom(from))
            if (r.getReferenceType() == ghidra.program.model.symbol.RefType.CALL_OVERRIDE_UNCONDITIONAL)
                refs.delete(r);
        Reference r = refs.addMemoryReference(from, target.getEntryPoint(),
                ghidra.program.model.symbol.RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
        refs.setPrimary(r, true);
        constSlotCalls.add(from);
    }

    private void constantCallSlots32() throws Exception {
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        Memory mem = currentProgram.getMemory();
        java.util.Map<Address, Function> done = new java.util.HashMap<>();
        int typed = 0, written = 0, external = 0, calls = 0;
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall() || !ins.getFlowType().isComputed()) continue;
            if (!"CALL".equals(ins.getMnemonicString())) continue;
            // (`call dword ptr [abs]`: a memory operand of one address and no register)
            // (Ghidra gives the operand as the slot's Address, or as a Scalar)
            Object[] ops = ins.getOpObjects(0);
            if (ops.length != 1) continue;
            Address slot;
            if (ops[0] instanceof Address) slot = (Address) ops[0];
            else if (ops[0] instanceof Scalar)
                slot = currentProgram.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(((Scalar) ops[0]).getUnsignedValue());
            else continue;
            if (done.containsKey(slot)) {
                if (done.get(slot) != null) {
                    overrideCall(refs, ins, done.get(slot));
                    calls++;
                }
                continue;
            }
            done.put(slot, null);
            if (!mem.contains(slot)) continue;
            Data have = getDataAt(slot);
            if (have != null && have.isPointer() && have.getValue() instanceof Address
                    && ((Address) have.getValue()).isExternalAddress()) {
                external++;
                continue;
            }
            boolean importRef = false, writes = false;
            for (Reference r : refs.getReferencesFrom(slot)) importRef |= r.isExternalReference();
            for (Reference r : refs.getReferencesTo(slot)) writes |= r.getReferenceType().isWrite();
            if (importRef) {
                external++;
                continue;
            }
            if (writes) {
                written++;
                continue;
            }
            int v;
            try {
                v = mem.getInt(slot);
            } catch (Exception ex) {
                continue;
            }
            Function f = getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(v & 0xffffffffL));
            if (f == null) continue;
            done.put(slot, f);
            typed++;
            overrideCall(refs, ins, f);
            calls++;
        }
        println(String.format("ApplyFacts: constant call slots %d, their calls overridden %d (slots written %d, " +
                "imports %d)", typed, calls, written, external));
    }

    // data/names.json: functions identified by hand, with the evidence as a comment.
    private void applyNames(JsonObject root) throws Exception {
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = functionAt(addr(e.getKey()));
            if (f == null) continue;
            JsonObject n = e.getValue().getAsJsonObject();
            name(f, n.has("ns") ? n.get("ns").getAsString() : "Global", n.get("name").getAsString());
            if (n.has("evidence")) setPlateComment(f.getEntryPoint(), "identified: " + n.get("evidence").getAsString());
        }
    }

    // typetags.json: the classes a function allocates or frees, as tags and a comment.
    private void applyTypeTags(JsonObject root) throws Exception {
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) continue;
            StringBuilder sb = new StringBuilder();
            for (JsonElement c : e.getValue().getAsJsonArray()) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(c.getAsString());
            }
            String line = "types: " + sb;
            String old = f.getComment();
            if (old == null || !old.contains("types: ")) {
                f.setComment(old == null ? line : old + "\n" + line);
            }
            tagged++;
        }
    }

    // Tags are derived facts: when an extractor stops claiming a function (a fixed bug,
    // a verified reference), its old tag must go too. Removes every tag with this prefix
    // from functions outside `keep`.
    private int dropStaleTags(String prefix, java.util.Set<String> keep) {
        int dropped = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String key = "0x" + Long.toHexString(f.getEntryPoint().getOffset());
            for (var tag : new java.util.ArrayList<>(f.getTags())) {
                if (tag.getName().startsWith(prefix) && !keep.contains(key)) {
                    f.removeTag(tag.getName());
                    dropped++;
                }
            }
        }
        return dropped;
    }

    // noreturn.json: functions that never return (tools/noreturn.py). The decompiler reads
    // the flag at decompile time, so callers stop showing code after these calls.
    private int noreturnSet;

    // The words atomic instructions work on (`xchg [m], r`, `lock cmpxchg`, `lock xadd`, any `lock`
    // op) at fixed addresses, volatile: another thread changes them. Not so, the decompiler folds a
    // spin lock's retry, `mov eax, 1; xchg [g], eax; test eax, eax; jne`, as if this thread were the
    // only one: it wrote 1 on the first try, so the exchange "reads 1" forever, `do { LOCK();
    // UNLOCK(); } while (true);`, and the waiter never took the lock (rhtest msvc-14.51-x86 win-O2's
    // spinners, 2026-10-27). The address from the instruction's references, or a `mov r, imm` just
    // before it for `[r]`.
    private void applyAtomicVolatile() throws Exception {
        java.util.Set<Address> targets = new java.util.TreeSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            String m = ins.getMnemonicString().toUpperCase();
            boolean atomic = m.startsWith("XCHG") || m.contains("LOCK") || m.startsWith("CMPXCHG") || m.startsWith("XADD");
            if (!atomic) continue;
            int memOp = -1;
            for (int i = 0; i < ins.getNumOperands(); i++) {
                int t = ins.getOperandType(i);
                if ((t & ghidra.program.model.lang.OperandType.ADDRESS) != 0 || (t & ghidra.program.model.lang.OperandType.DYNAMIC) != 0) {
                    memOp = i;
                    break;
                }
            }
            if (memOp < 0) continue;                       // (xchg of two registers)
            Address found = null;
            for (Reference r : ins.getOperandReferences(memOp)) {
                if (r.getToAddress().isMemoryAddress()) { found = r.getToAddress(); break; }
            }
            if (found == null) {
                // (`[ecx]` with `mov ecx, imm` a few instructions before, nothing between writing ecx)
                Object[] objs = ins.getOpObjects(memOp);
                if (objs.length == 1 && objs[0] instanceof ghidra.program.model.lang.Register) {
                    ghidra.program.model.lang.Register reg = (ghidra.program.model.lang.Register) objs[0];
                    Instruction p = ins.getPrevious();
                    for (int k = 0; k < 4 && p != null; k++, p = p.getPrevious()) {
                        Object[] res = p.getResultObjects();
                        boolean writes = false;
                        for (Object o : res) if (o instanceof ghidra.program.model.lang.Register
                                && ((ghidra.program.model.lang.Register) o).getBaseRegister().equals(reg.getBaseRegister())) writes = true;
                        if (!writes) continue;
                        if (p.getMnemonicString().equalsIgnoreCase("MOV") && p.getScalar(1) != null) {
                            Address a = toAddr(p.getScalar(1).getUnsignedValue());
                            if (currentProgram.getMemory().contains(a)) found = a;
                        }
                        break;
                    }
                }
            }
            if (found != null && !currentProgram.getMemory().getBlock(found).isExecute()) targets.add(found);
        }
        int marked = 0;
        for (Address a : targets) {
            Data d = getDataAt(a);
            if (d == null && getDataContaining(a) == null) {
                try {
                    d = createData(a, ghidra.program.model.data.DWordDataType.dataType);
                } catch (Exception e) {
                    d = null;
                }
            }
            if (d == null) continue;
            MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.VOLATILE);
            marked++;
        }
        println("ApplyFacts: words atomic instructions work on made volatile " + marked + " of " + targets.size());
    }

    private void applyNoReturn(JsonObject root) throws Exception {
        java.util.Set<Address> listed = new java.util.HashSet<>();
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) continue;
            listed.add(f.getEntryPoint());
            if (f.hasNoReturn()) continue;
            f.setNoReturn(true);
            noreturnSet++;
        }
        // (x86: and one marked before, by an earlier session or Ghidra's analysis, that noreturn.py
        // no longer lists and that has a return instruction, unmarked. __security_check_cookie's
        // `repz ret` had been missed, it was marked, and stayed so after the fix, cutting off what
        // follows each of its 8,878 calls)
        int cleared = 0;
        java.util.List<Function> unmarked = new java.util.ArrayList<>();
        if (currentProgram.getDefaultPointerSize() == 4) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!f.hasNoReturn() || listed.contains(f.getEntryPoint()) || f.isThunk()) continue;
                boolean returns = false;
                // (or an SEH frame linked and a trap the flow ends on, `__try { __debugbreak(); }`:
                // it returns through its __except continuation, as noreturn.py has it. Ghidra's
                // own analysis marked rhtest seh's instructions() noreturn, its caller cut there)
                boolean linksEh = false, traps = false;
                for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                    String mn = in.getMnemonicString().toUpperCase();
                    if (mn.equals("MOV") && in.toString().toUpperCase().replace(" ", "").contains("FS:[0X0],")) linksEh = true;
                    if (mn.equals("INT3") || mn.equals("HLT") || mn.equals("UD2")) traps = true;
                    if (linksEh && traps) {
                        returns = true;
                        break;
                    }
                    if (in.getFlowType().isTerminal() && in.getMnemonicString().toUpperCase().contains("RET")) {
                        returns = true;
                        break;
                    }
                    // (or a jump out of its body, as noreturn.py counts one: VS2010's nested()
                    // returns through the join past its catch funclets, rhtest msvc-16.00-x86 eh-O2)
                    if (in.getFlowType().isJump()) {
                        for (Address t : in.getFlows()) {
                            if (!f.getBody().contains(t)) returns = true;
                        }
                        if (returns) break;
                    }
                }
                if (returns) {
                    f.setNoReturn(false);
                    cleared++;
                    unmarked.add(f);
                }
            }
        }
        // (and the bodies its callers were cut to at those calls given back: the flow goes on past
        // them now, but a body only grows when fixed up. A VS2010 client's 0x67fb80 stopped at its
        // call to 0x6761f0, Ghidra's analysis having marked it noreturn: its other 12 KB analysed by
        // no fact, decompiled whole, and an AddRef there called with no `this`, 2026-10-27)
        java.util.Set<Function> refit = new java.util.HashSet<>();
        for (Function f : unmarked) {
            for (ghidra.program.model.symbol.Reference r : getReferencesTo(f.getEntryPoint())) {
                if (!r.getReferenceType().isCall()) continue;
                Function caller = getFunctionContaining(r.getFromAddress());
                if (caller != null) refit.add(caller);
            }
        }
        // (and any body that ends at a call to a function that returns, the code after it no
        // function's: cut by a flag cleared in an earlier session, before callers were refit)
        if (currentProgram.getDefaultPointerSize() == 4) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) continue;
                for (ghidra.program.model.address.AddressRange r : f.getBody()) {
                    Instruction last = getInstructionContaining(r.getMaxAddress());
                    if (last == null || !last.getFlowType().isCall()) continue;
                    Address next = last.getMaxAddress().add(1);
                    if (f.getBody().contains(next) || getFunctionContaining(next) != null) continue;
                    boolean returns = true;
                    for (Address t : last.getFlows()) {
                        Function callee = getFunctionAt(t);
                        if (callee == null || callee.hasNoReturn()) returns = false;
                    }
                    if (returns && last.getFlows().length > 0) {
                        refit.add(f);
                        break;
                    }
                }
            }
        }
        for (Function caller : refit) CreateFunctionCmd.fixupFunctionBody(currentProgram, caller, monitor);
        println("ApplyFacts: marked " + noreturnSet + " functions noreturn (" + cleared + " that return unmarked, "
                + refit.size() + " callers' bodies refit)");
    }

    // varargs.json: variadic functions and their fixed parameter count (tools/varargs.py).
    // Marked varargs with only the fixed parameters, and the signature locked as IMPORTED so
    // the commit pass (CommitPrototypes.java, which re-derives only ANALYSIS and below) keeps
    // it: committed with all four register parameters, every caller passed its own r8/r9.
    private void applyVarargs(JsonObject root) throws Exception {
        int set = 0, user = 0, unset = 0;
        // a function an earlier session marked variadic that the facts no longer call one (the
        // text-based tools/varargs.py took a parameter passed on by reference for a va_start,
        // FUN_1417eec30's fourth, and its body decompiled `in_R9`): back to a fixed signature,
        // which applyProtos then gives the parameters the instructions read. Only what this script
        // marked (IMPORTED): FID's library signatures are ANALYSIS, user ones USER_DEFINED
        JsonObject want = root.getAsJsonObject("functions");
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!f.hasVarArgs() || f.getSignatureSource() != SourceType.IMPORTED) continue;
            if (want.has("0x" + f.getEntryPoint().toString())) continue;
            f.setVarArgs(false);
            f.setSignatureSource(SourceType.ANALYSIS);
            unset++;
        }
        println("ApplyFacts: no longer variadic " + unset);
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) continue;
            if (f.getSignatureSource() == SourceType.USER_DEFINED) {
                user++;
                continue;
            }
            int fixed = e.getValue().getAsInt();
            vaFixed.put(f.getEntryPoint(), fixed);
            Parameter[] cur = f.getParameters();
            if (f.hasVarArgs() && cur.length == fixed && f.getSignatureSource() == SourceType.IMPORTED) continue;
            // (fewer than the fixed count so far: the rest as plain registers, which applyProtos
            // then types; FUN_14253a9a0 takes six and starts its va_list past the sixth)
            List<Variable> params = new ArrayList<>();
            for (int i = 0; i < fixed; i++) {
                params.add(i < cur.length ? new ParameterImpl(cur[i].getName(), cur[i].getDataType(), currentProgram)
                        : new ParameterImpl("param_" + (i + 1), Undefined.getUndefinedDataType(8), currentProgram));
            }
            f.updateFunction(null, null, params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.IMPORTED);
            f.setVarArgs(true);
            f.setSignatureSource(SourceType.IMPORTED);
            set++;
        }
        println("ApplyFacts: marked " + set + " functions variadic (kept " + user + " user signatures)");
    }

    // The call targets and pointed-to code no function covered (protos.py, protos32.py "leaves",
    // "pointed"), made functions
    private void applyLeaves(JsonObject root) throws Exception {
        if (!root.has("leaves")) return;
        // (a leaf a pointer reaches is an entry point even inside a body Ghidra drew over it,
        // a callback it absorbed through a jump: made there too, and the body it was taken
        // from fixed up. A leaf only called from inside a function's body is the anti-tamper
        // junk's call into the middle of code, and is left alone)
        java.util.Set<Address> pointed = new java.util.HashSet<>();
        if (root.has("pointed")) {
            for (JsonElement l : root.getAsJsonArray("pointed")) pointed.add(addr(l.getAsString()));
        }
        int made = 0, split = 0;
        for (JsonElement l : root.getAsJsonArray("leaves")) {
            Address a = addr(l.getAsString());
            if (getFunctionAt(a) != null || partOfAnother.contains(a)) continue;
            Function in = getFunctionContaining(a);
            if (in != null && !pointed.contains(a)) continue;
            if (getInstructionAt(a) == null) disassemble(a);
            if (new CreateFunctionCmd(a).applyTo(currentProgram, monitor)) {
                made++;
                if (in != null) {
                    split++;
                    CreateFunctionCmd.fixupFunctionBody(currentProgram, in, monitor);
                }
            }
        }
        println("ApplyFacts: leaf functions created " + made + " of " + root.getAsJsonArray("leaves").size()
                + " (" + split + " inside another function's body, " + pointed.size() + " reached by a pointer)");
    }

    // protos.json (tools/protos.py): each function's parameters as its instructions read them,
    // in place of the Decompiler Parameter ID guesses CommitPrototypes.java used to commit
    // (FUN_1414fc8b0 reads dx and r8w and was committed as `(uint)`: its body then read registers
    // the decompiler lost track of). Each position keeps Ghidra's type when the kind agrees
    // (integer, float, double), and otherwise takes one of the width read. Locked as IMPORTED.
    // An `open` function (it leaves through an indirect tail call, so it may pass registers on
    // unseen) only ever gains parameters.
    private void applyProtos(JsonObject root) throws Exception {
        int set = 0, same = 0, skipped = 0;
        // the call targets no function covered (leaves without .pdata, tools/protos.py): made
        // functions first, so they decompile and take their prototypes below
        applyLeaves(root);
        // the code after a run of the clean exe's nops: Ghidra's disassembly stopped at the end of
        // the run, leaving the rest of the function undefined bytes, and the decompiler went on
        // through them alone, taking the tail call it found there for code of its own
        // (FUN_141832090 ran into FUN_1418a72a0, its loop's registers `in_R9`, `unaff_RDI`)
        int resumed = 0, rounds = 0;
        boolean more = true;
        while (more && rounds++ < 12) {
            more = false;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) continue;
                boolean grew = false;
                for (ghidra.program.model.address.AddressRange r : f.getBody()) {
                    Instruction last = getInstructionContaining(r.getMaxAddress());
                    if (last == null || !last.getFlowType().hasFallthrough()) continue;
                    Address next = last.getMaxAddress().add(1);
                    if (currentProgram.getListing().getUndefinedDataAt(next) == null) continue;
                    if (getFunctionAt(next) != null) continue;
                    // (the disassembler stops part way along a long run of one instruction, its
                    // guard against decoding data: the run of nops is decoded here without flow,
                    // and the flow resumes at the code after it)
                    Address code = next;
                    int nops = 0;
                    while (nops < 4096 && currentProgram.getMemory().contains(code)
                            && (currentProgram.getMemory().getByte(code) & 0xff) == 0x90
                            && currentProgram.getListing().getUndefinedDataAt(code) != null) {
                        code = code.add(1);
                        nops++;
                    }
                    if (nops > 0) {
                        new DisassembleCommand(new ghidra.program.model.address.AddressSet(next, code.subtract(1)),
                                null, false).applyTo(currentProgram, monitor);
                    }
                    if (currentProgram.getListing().getUndefinedDataAt(code) != null) {
                        new DisassembleCommand(code, null, true).applyTo(currentProgram, monitor);
                    }
                    if (getInstructionAt(next) != null) {
                        grew = true;
                        resumed++;
                    }
                }
                if (grew) {
                    CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
                    more = true;
                }
            }
        }
        println("ApplyFacts: function code resumed after undisassembled bytes " + resumed);
        // each jump from one function to another's start, now that the code holding it is
        // disassembled: a call that returns, the callee a function of its own and the caller's
        // body recomputed. Left a branch, the callee's code read as the caller's (FUN_141832090
        // decompiled FUN_1418a72a0's loop as its own, reading the registers that callee's own
        // caller had set: `in_R9`, `unaff_RDI`)
        if (root.has("tail_jumps")) {
            // first, a jump an earlier session marked and the facts no longer list goes back to a
            // branch: the overrides are saved with the program and nothing else takes them off.
            // A thunk-resolved jump marked once (`je 0x14065f73d`, into a lone `jmp`) stayed a
            // call to a non-function after protos.py stopped listing it, `func_0x00014065f73d()`
            // with no arguments in 41 functions (2026-10-18)
            java.util.Set<Address> listed = new java.util.HashSet<>();
            for (String k : root.getAsJsonObject("tail_jumps").keySet()) listed.add(addr(k));
            int cleared = 0;
            java.util.Set<Function> refit = new java.util.HashSet<>();
            InstructionIterator it = currentProgram.getListing().getInstructions(true);
            while (it.hasNext()) {
                Instruction insn = it.next();
                if (insn.getFlowOverride() == FlowOverride.CALL_RETURN && insn.getFlowType().isJump()
                        && !listed.contains(insn.getAddress())) {
                    insn.setFlowOverride(FlowOverride.NONE);
                    Function c = getFunctionContaining(insn.getAddress());
                    if (c != null) refit.add(c);
                    cleared++;
                }
            }
            for (Function c : refit) CreateFunctionCmd.fixupFunctionBody(currentProgram, c, monitor);
            println("ApplyFacts: tail jumps no longer listed, back to branches " + cleared);
            int marked = 0;
            for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("tail_jumps").entrySet()) {
                Address j = addr(e.getKey());
                Address t = addr(e.getValue().getAsString());
                Function c = getFunctionContaining(j);
                Instruction insn = getInstructionAt(j);
                if (c == null || insn == null || c.getEntryPoint().equals(t)) continue;
                if (insn.getFlowOverride() == FlowOverride.CALL_RETURN) continue;
                if (getFunctionAt(t) == null && !partOfAnother.contains(t)) {
                    if (getInstructionAt(t) == null) disassemble(t);
                    new CreateFunctionCmd(t).applyTo(currentProgram, monitor);
                }
                insn.setFlowOverride(FlowOverride.CALL_RETURN);
                if (c.getBody().contains(t)) {
                    CreateFunctionCmd.fixupFunctionBody(currentProgram, c, monitor);
                }
                marked++;
            }
            println("ApplyFacts: tail jumps marked calls that return " + marked);
        }
        // no function is decompiled into its callers: each is translated on its own, and inlined
        // its body reads its callers' callers' registers (`in_R9`, `unaff_RDI`)
        int inlined = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isInline()) {
                f.setInline(false);
                inlined++;
            }
        }
        println("ApplyFacts: functions no longer inlined into their callers " + inlined);
        // a function Ghidra made a thunk whose code does more than jump (`mov dl, 1; jmp
        // FUN_14216a080`): decompiled as the target, its callers passed the target's second
        // parameter themselves and read `in_DL` (FUN_141ef4090, 2026-10-16). A function of its own
        int unthunked = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!f.isThunk() || f.isExternal()) continue;
            Instruction first = getInstructionAt(f.getEntryPoint());
            if (first == null || first.getFlowType().isJump()) continue;
            f.setThunkedFunction(null);
            unthunked++;
        }
        println("ApplyFacts: thunks that do more than jump made functions " + unthunked);
        // functions that do nothing (spills and a ret: the release build's log calls) were given
        // the cspec's security_check_cookie fixup on 2026-10-16, which is no code: but no code
        // also leaves the call's return-address push in place, so the stack drifted 8 bytes a call
        // and the decompiler lost it in 10 of the 85 callers (FUN_142586960: `auStackY_1e8`, the
        // pushes stored as `*(puVar17 + -8) = 0x142586e03`, its second loop behind a 32-byte
        // value; 2026-10-17). They get a calling convention that keeps every register instead
        // (applyNoops); the fixup comes off
        if (root.has("noops")) {
            int cleared = 0;
            for (JsonElement n : root.getAsJsonArray("noops")) {
                Function f = getFunctionAt(addr(n.getAsString()));
                if (f == null || f.isExternal()) continue;
                if ("security_check_cookie".equals(f.getCallFixup())) {
                    f.setCallFixup(null);
                    cleared++;
                }
            }
            println("ApplyFacts: no-op call fixups taken off functions that do nothing " + cleared);
        }
        // each `call __chkstk` of a large frame, a 5-byte nop in Ghidra's copy (tools/protos.py)
        if (root.has("chkstk_calls")) {
            int nopped = 0, done = 0, missing = 0;
            byte[] nop5 = new byte[] { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
            for (JsonElement c : root.getAsJsonArray("chkstk_calls")) {
                Address at = addr(c.getAsString());
                Instruction insn = getInstructionAt(at);
                if (insn == null) {
                    missing++;
                    continue;
                }
                byte[] code = insn.getBytes();
                if (code.length == 5 && (code[0] & 0xff) == 0x0f && (code[1] & 0xff) == 0x1f) {
                    done++;
                    continue;
                }
                if (code.length != 5 || (code[0] & 0xff) != 0xe8) {
                    missing++;
                    continue;
                }
                clearListing(at, at.add(4));
                currentProgram.getMemory().setBytes(at, nop5);
                new DisassembleCommand(at, null, false).applyTo(currentProgram, monitor);
                nopped++;
            }
            println("ApplyFacts: __chkstk calls made nops " + nopped + " (already " + done + "), not a call " + missing);
        }
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            // (a variadic function this script marked takes its fixed parameters from here too)
            Integer fixed = f != null ? vaFixed.get(f.getEntryPoint()) : null;
            if (f == null || f.isThunk() || f.isExternal() || (f.hasVarArgs() && fixed == null)
                    || f.getSignatureSource() == SourceType.USER_DEFINED) {
                skipped++;
                continue;
            }
            JsonObject o = e.getValue().getAsJsonObject();
            JsonArray want = o.getAsJsonArray("params");
            boolean open = o.has("open") && o.get("open").getAsBoolean();
            Parameter[] cur = f.getParameters();
            int n = fixed != null ? fixed : open ? Math.max(want.size(), cur.length) : want.size();
            // a 16-byte value in an xmm register (a vector argument or result): Win64 as Ghidra
            // models it has none, and passes and returns 16 bytes through memory, so these are
            // placed by hand (custom storage). Returned through a hidden pointer, the sincos
            // FUN_14240ad20's two lanes were `extraout_XMM0_Db` in 17 callers, and the hidden
            // pointer moved every parameter of FUN_141345190 one register on (2026-10-16)
            boolean custom = o.has("ret") && "v".equals(o.getAsJsonArray("ret").get(0).getAsString());
            for (int i = 0; i < Math.min(n, want.size()); i++) {
                custom |= "v".equals(want.get(i).getAsJsonArray().get(0).getAsString());
            }
            List<Variable> params = new ArrayList<>();
            boolean differs = n != cur.length || custom != f.hasCustomVariableStorage();
            for (int i = 0; i < n; i++) {
                String kind = i < want.size() ? want.get(i).getAsJsonArray().get(0).getAsString() : "?";
                int size = i < want.size() ? want.get(i).getAsJsonArray().get(1).getAsInt() : 8;
                DataType have = i < cur.length ? cur[i].getDataType() : null;
                DataType dt = paramType(kind, size, have);
                if ("i".equals(kind) && intParams.getOrDefault(f.getEntryPoint(), Set.of()).contains(i + 1)) {
                    dt = concreteInt(size);
                }
                if (have == null || !dt.isEquivalent(have)) differs = true;
                String name = i < cur.length ? cur[i].getName() : "param_" + (i + 1);
                if (name.equals("this")) name = "param_" + (i + 1);
                params.add(custom ? new ParameterImpl(name, dt, paramStorage(i, kind, dt), currentProgram)
                        : new ParameterImpl(name, dt, currentProgram));
            }
            // the result, as wide as the direct callers read it (`test al, al`: a byte). Only
            // functions with direct callers have one: what only a vtable reaches keeps Ghidra's
            // with no result fact (no caller reads it, the function writes nothing of rax) it is
            // void: kept as an earlier pass typed it, a static initializer that registers an atexit
            // handler returned its stack pointer (`BADSPACEBASE`, 106 stubs, 2026-10-16)
            ReturnParameterImpl ret = null;
            DataType have = f.getReturnType();
            DataType dt = o.has("ret")
                    ? returnType(o.getAsJsonArray("ret").get(0).getAsString(), o.getAsJsonArray("ret").get(1).getAsInt(), have)
                    : (open ? have : ghidra.program.model.data.VoidDataType.dataType);
            if (!dt.isEquivalent(have)) {
                differs = true;
                ret = new ReturnParameterImpl(dt, currentProgram);
            }
            if (custom) {
                String rk = o.has("ret") ? o.getAsJsonArray("ret").get(0).getAsString() : null;
                ret = new ReturnParameterImpl(dt, returnStorage(rk, dt), currentProgram);
            }
            // `__thiscall` adds a `this` typed by the class (FID's library signatures): on x64 it
            // is the same registers as __fastcall, and `this` an ordinary first parameter
            String cc = "__thiscall".equals(f.getCallingConventionName()) ? "__fastcall" : null;
            if (cc != null) differs = true;
            if (!differs && f.getSignatureSource() == SourceType.IMPORTED) {
                same++;
                continue;
            }
            f.updateFunction(cc, ret != null ? ret : f.getReturn(), params,
                    custom ? FunctionUpdateType.CUSTOM_STORAGE : FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.IMPORTED);
            if (fixed != null) f.setVarArgs(true);
            f.setSignatureSource(SourceType.IMPORTED);
            set++;
            if (custom) customs++;
        }
        println("ApplyFacts: prototypes committed " + set + " (" + customs + " with xmm vectors placed by hand), already so "
                + same + ", skipped " + skipped);
        java.util.Set<Address> noops = new java.util.HashSet<>();
        if (root.has("noops")) for (JsonElement e : root.getAsJsonArray("noops")) noops.add(addr(e.getAsString()));
        java.util.Set<Address> keepXmm0 = new java.util.HashSet<>();
        if (root.has("keep_xmm0")) for (JsonElement e : root.getAsJsonArray("keep_xmm0")) keepXmm0.add(addr(e.getAsString()));
        applyKeepConventions(keepXmm0, noops);
    }

    // the volatile integer registers each function preserves (tools/preserved.py), read in run()
    private final Map<Address, java.util.List<String>> preserved = new HashMap<>();
    private boolean preservedChosen;

    // Each function's calling convention from what it leaves as it found it: everything (a no-op),
    // xmm0 (protos.py keep_xmm0), and the volatile integer registers (preserved.py), one
    // convention per combination, __fastcall_keep_r8_r9_xmm0 and so on. A function that has one of
    // these and no longer qualifies goes back to __fastcall; any other convention is left alone.
    private void applyKeepConventions(java.util.Set<Address> keepXmm0, java.util.Set<Address> noops) throws Exception {
        Map<Address, String> want = new HashMap<>();
        java.util.Set<Address> every = new java.util.HashSet<>(preservedChosen ? java.util.Collections.emptySet() : keepXmm0);
        every.addAll(noops);
        every.addAll(preserved.keySet());
        for (Address a : every) {
            if (noops.contains(a)) {
                want.put(a, KEEP_ALL);
                continue;
            }
            java.util.List<String> regs = preserved.getOrDefault(a, java.util.Collections.emptyList());
            boolean x = preservedChosen ? regs.contains("XMM0") : keepXmm0.contains(a);
            if (preservedChosen && regs.size() == 1 && x) {
                want.put(a, KEEP_XMM0);
                continue;
            }
            if (regs.isEmpty()) {
                want.put(a, KEEP_XMM0);
                continue;
            }
            StringBuilder n = new StringBuilder("__fastcall_keep");
            for (String r : KEEPABLE) if (regs.contains(r)) n.append('_').append(r.toLowerCase());
            if (x) n.append("_xmm0");
            want.put(a, n.toString());
        }
        // the conventions, each added (or replaced) once
        Class<?> se = Function.class.getClassLoader().loadClass("ghidra.program.database.SpecExtension");
        Object ext = se.getConstructor(ghidra.program.model.listing.Program.class).newInstance(currentProgram);
        java.lang.reflect.Method add = se.getMethod("addReplaceCompilerSpecExtension", String.class,
                ghidra.util.task.TaskMonitor.class);
        for (String name : new java.util.TreeSet<>(want.values())) add.invoke(ext, conventionXml(name), monitor);
        reclaimConventionSlots(want);
        int set = 0, kept = 0, reset = 0, fell = 0;
        // The program holds only so many convention names (a byte's worth, and a name once used
        // keeps its slot): with xmm1-xmm5 there were 355 kinds, and 285 of them failed "allocation
        // capacity exceeded" (2026-10-18). The commonest go first; a function whose own does not
        // fit gets the working one that keeps the most of its registers and nothing more (a
        // register it does not keep is only killed by the call, as under __fastcall)
        Map<String, Integer> uses = new HashMap<>();
        for (String w : want.values()) uses.merge(w, 1, Integer::sum);
        java.util.List<Function> order = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) order.add(f);
        order.sort((x, y) -> Integer.compare(uses.getOrDefault(want.get(y.getEntryPoint()), 0),
                uses.getOrDefault(want.get(x.getEntryPoint()), 0)));
        java.util.Set<String> working = new java.util.HashSet<>(), failed = new java.util.HashSet<>();
        for (Function f : order) {
            String cur = f.getCallingConventionName();
            boolean ours = cur != null && cur.startsWith("__fastcall_keep");
            String w = want.get(f.getEntryPoint());
            if (w == null) {
                if (ours) {
                    f.setCallingConvention("__fastcall");
                    reset++;
                }
                continue;
            }
            if (f.isExternal() || f.isThunk() || f.hasCustomVariableStorage()) continue;
            if (w.equals(cur)) {
                working.add(w);
                kept++;
                continue;
            }
            // (only over __fastcall or one of these: a function given another convention keeps it)
            if (cur != null && !cur.equals("__fastcall") && !ours && !cur.equals("unknown") && !cur.equals("default")) continue;
            String c = failed.contains(w) ? fallback(w, working) : w;
            while (true) {
                try {
                    f.setCallingConvention(c);
                } catch (Exception e) {
                    // (a refused name is reported as an error and the convention left as it was)
                }
                if (c.equals(f.getCallingConventionName()) || c.equals("__fastcall")) break;
                failed.add(c);
                working.remove(c);
                c = fallback(w, working);
            }
            working.add(c);
            if (!c.equals(w)) fell++;
            set++;
        }
        println("ApplyFacts: keep conventions (" + new java.util.TreeSet<>(want.values()).size() + " kinds, "
                + failed.size() + " beyond the program's capacity) given to " + set + " functions ("
                + fell + " with a narrower one; already " + kept + "), " + reset + " back to __fastcall");
    }

    // The program's table of convention names holds 126 (a signed byte's ids) and never lets one go:
    // every keep convention an earlier session assigned kept its slot after nothing used it, and on
    // 2026-10-18 one slot was left, so 33 of the 49 conventions tools/preserved.py chose could not
    // be named and 5,488 functions fell back to narrower ones. Before assigning: every function
    // whose keep convention is about to change goes to __fastcall, and each keep name no function
    // and no function definition then uses is deleted from the table (its record, through the
    // adapter the data type manager keeps), freeing its id. Anything unexpected and it is left as
    // it was: the assignment below still falls back to what fits.
    private void reclaimConventionSlots(Map<Address, String> want) {
        try {
            int moved = 0;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                String cur = f.getCallingConventionName();
                if (cur != null && cur.startsWith("__fastcall_keep") && !cur.equals(want.get(f.getEntryPoint()))) {
                    f.setCallingConvention("__fastcall");
                    moved++;
                }
            }
            java.util.Set<String> used = new java.util.HashSet<>();
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getCallingConventionName() != null) used.add(f.getCallingConventionName());
            }
            ghidra.program.model.data.DataTypeManager dtm = currentProgram.getDataTypeManager();
            java.util.Iterator<ghidra.program.model.data.DataType> all = dtm.getAllDataTypes();
            while (all.hasNext()) {
                ghidra.program.model.data.DataType d = all.next();
                if (d instanceof ghidra.program.model.data.FunctionDefinition fd && fd.getCallingConventionName() != null) {
                    used.add(fd.getCallingConventionName());
                }
            }
            Class<?> c = dtm.getClass();
            while (c != null && !c.getSimpleName().equals("DataTypeManagerDB")) c = c.getSuperclass();
            java.lang.reflect.Field af = c.getDeclaredField("callingConventionAdapter");
            af.setAccessible(true);
            Object adapter = af.get(dtm);
            java.lang.reflect.Method names = adapter.getClass().getDeclaredMethod("getCallingConventionNames");
            names.setAccessible(true);
            names.invoke(adapter);      // (fills the adapter's name -> id map)
            java.lang.reflect.Field mf = adapter.getClass().getDeclaredField("callingConventionNameToIDMap");
            mf.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<String, Byte> ids = new HashMap<>((Map<String, Byte>) mf.get(adapter));
            java.lang.reflect.Field tf = adapter.getClass().getDeclaredField("callingConventionTable");
            tf.setAccessible(true);
            // (through reflection: the script bundle's manifest does not import the db package, as it
            // did not import ghidra.program.model.pcode, see applyCallsites)
            Object table = tf.get(adapter);
            // (keyed by a byte field, not a long: "Field key required")
            Class<?> fieldClass = table.getClass().getClassLoader().loadClass("db.Field");
            Class<?> byteField = table.getClass().getClassLoader().loadClass("db.ByteField");
            java.lang.reflect.Constructor<?> key = byteField.getConstructor(byte.class);
            java.lang.reflect.Method delete = table.getClass().getMethod("deleteRecord", fieldClass);
            int freed = 0;
            for (Map.Entry<String, Byte> e : ids.entrySet()) {
                if (e.getKey().startsWith("__fastcall_keep") && !used.contains(e.getKey())) {
                    if ((Boolean) delete.invoke(table, key.newInstance(e.getValue()))) freed++;
                }
            }
            java.lang.reflect.Method inv = adapter.getClass().getDeclaredMethod("invalidateCache");
            inv.setAccessible(true);
            inv.invoke(adapter);
            dtm.getClass().getMethod("invalidateCache").invoke(dtm);
            println("ApplyFacts: convention slots: " + moved + " functions moved off a changing convention, "
                    + freed + " unused names freed of " + ids.size());
        } catch (Throwable t) {
            println("ApplyFacts: convention slots not reclaimed (" + t + "); assigning within what is left");
        }
    }

    // the registers a keep convention leaves alone, from its name
    private static java.util.Set<String> keptBy(String name) {
        java.util.Set<String> out = new java.util.HashSet<>();
        if (KEEP_ALL.equals(name)) {
            out.addAll(java.util.Arrays.asList(KEEPABLE));
            out.add("XMM0");
            out.add("RAX");
            return out;
        }
        if (KEEP_XMM0.equals(name)) {
            out.add("XMM0");
            return out;
        }
        if (name.startsWith("__fastcall_keep_")) {
            for (String t : name.substring("__fastcall_keep_".length()).split("_")) out.add(t.toUpperCase());
        }
        return out;
    }

    // the working convention that keeps the most of what `want` keeps and nothing else, or __fastcall
    private static String fallback(String want, java.util.Set<String> working) {
        java.util.Set<String> regs = keptBy(want);
        String best = "__fastcall";
        int size = 0;
        for (String w : working) {
            java.util.Set<String> k = keptBy(w);
            if (regs.containsAll(k) && (k.size() > size || (k.size() == size && w.compareTo(best) < 0))) {
                best = w;
                size = k.size();
            }
        }
        return best;
    }

    private int customs;

    // The functions xmm0 comes out of as it went in (tools/protos.py: none of their instructions
    // writes it and all they call are such functions). The whole-program build keeps a value in
    // xmm0 across a call to one; under Win64's __fastcall, where xmm0 is killed by any call, the
    // decompiler printed the value after the call `extraout_XMM0` (FUN_140315680). A calling
    // convention of their own, __fastcall with xmm0 among the unaffected registers, added to the
    // program as a compiler-spec extension
    private static final String KEEP_XMM0 = "__fastcall_keepxmm0";
    // and the functions that do nothing at all (tools/protos.py `noops`): __fastcall with every
    // register unaffected, which is what they do, so a value kept in rax or a volatile register
    // across a call to one stays the same variable (not `extraout_EAX`)
    private static final String KEEP_ALL = "__fastcall_keepall";

    // the volatile integer registers a convention keeps beside xmm0 (tools/preserved.py), as named
    // (and xmm1-xmm5, as preserved.py finds them since 2026-10-18)
    private static final String[] KEEPABLE = { "RAX", "RCX", "RDX", "R8", "R9", "R10", "R11",
            "XMM1", "XMM2", "XMM3", "XMM4", "XMM5" };

    private static String conventionXml(String name) {
        // __fastcall_keepxmm0, __fastcall_keepall, or __fastcall_keep_<regs>[_xmm0]
        boolean all = KEEP_ALL.equals(name);
        boolean xmm0 = KEEP_XMM0.equals(name) || name.endsWith("_xmm0");
        java.util.Set<String> regs = new java.util.HashSet<>();
        if (name.startsWith("__fastcall_keep_")) {
            for (String r : KEEPABLE) {
                if (java.util.Arrays.asList(name.substring("__fastcall_keep_".length()).split("_")).contains(r.toLowerCase())) {
                    regs.add(r);
                }
            }
        }
        String g = "<group><pentry minsize=\"4\" maxsize=\"8\" metatype=\"float\"><register name=\"XMM%d_Qa\"/></pentry>"
                + "<pentry minsize=\"1\" maxsize=\"8\"><register name=\"%s\"/></pentry></group>";
        StringBuilder x = new StringBuilder();
        x.append("<prototype name=\"").append(name).append("\" extrapop=\"8\" stackshift=\"8\">");
        x.append("<input pointermax=\"8\">");
        String[] gpr = { "RCX", "RDX", "R8", "R9" };
        for (int i = 0; i < 4; i++) x.append(String.format(g, i, gpr[i]));
        x.append("<pentry minsize=\"1\" maxsize=\"500\" align=\"8\"><addr offset=\"40\" space=\"stack\"/></pentry>");
        x.append("<rule><datatype name=\"struct\" sizes=\"3,5,6,7\"/><convert_to_ptr/></rule></input>");
        x.append("<output><pentry minsize=\"4\" maxsize=\"8\" metatype=\"float\"><register name=\"XMM0_Qa\"/></pentry>");
        x.append("<pentry minsize=\"1\" maxsize=\"8\"><register name=\"RAX\"/></pentry>");
        x.append("<rule><datatype name=\"struct\" sizes=\"3,5,6,7\"/><hidden_return/></rule></output>");
        x.append("<unaffected><varnode space=\"ram\" offset=\"0\" size=\"8\"/>");
        for (String r : new String[] { "RBX", "RBP", "RDI", "RSI", "RSP", "R12", "R13", "R14", "R15", "DF", "GS_OFFSET",
                "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15" }) {
            x.append("<register name=\"").append(r).append("\"/>");
        }
        if (xmm0 || all) x.append("<register name=\"XMM0\"/>");
        if (!all) {
            for (String r : regs) x.append("<register name=\"").append(r).append("\"/>");
        }
        if (all) {
            for (String r : new String[] { "RAX", "RCX", "RDX", "R8", "R9", "R10", "R11",
                    "XMM1", "XMM2", "XMM3", "XMM4", "XMM5" }) {
                x.append("<register name=\"").append(r).append("\"/>");
            }
            x.append("</unaffected>");
        } else {
            // every volatile register but xmm0, as __fastcall kills them. With only RAX listed,
            // rcx, rdx, r8-r11 and xmm1-5 were neither killed nor kept, and the decompiler let a
            // value flow through a call in them: `FUN_1405ee730(in_R8)` in FUN_1405ef2d0, which
            // passes rcx on untouched, and in_R8/in_R9/in_R10/in_R11 read around calls to the
            // 12,471 functions that have this convention (2026-10-18)
            // (and no <killedbycall> at all when it would be empty: a convention that keeps every
            // volatile register, rax among them since 2026-10-18, failed the spec's schema with an
            // empty one, "uncompleted content model")
            StringBuilder killed = new StringBuilder();
            for (String r : new String[] { "RAX", "RCX", "RDX", "R8", "R9", "R10", "R11",
                    "XMM1", "XMM2", "XMM3", "XMM4", "XMM5" }) {
                if (!regs.contains(r)) killed.append("<register name=\"").append(r).append("\"/>");
            }
            if (!xmm0) killed.append("<register name=\"XMM0\"/>");
            x.append("</unaffected>");
            if (killed.length() > 0) x.append("<killedbycall>").append(killed).append("</killedbycall>");
        }
        x.append("<localrange><range space=\"stack\" first=\"0xfffffffffff0bdc1\" last=\"0xffffffffffffffff\"/>");
        x.append("<range space=\"stack\" first=\"8\" last=\"39\"/></localrange></prototype>");
        return x.toString();
    }

    // the convention `name` (a compiler-spec extension, added once) on the listed functions but
    // `skip`, and __fastcall back on any that has it and is no longer listed
    private void applyConvention(String name, JsonArray list, java.util.Set<Address> skip) throws Exception {
        {
            // (every session, add or replace: added only when missing, a corrected definition
            // never reached a program that had the old one)
            // (through Ghidra's own class loader, as JumpTable: the script bundle does not import
            // ghidra.program.database)
            Class<?> se = Function.class.getClassLoader().loadClass("ghidra.program.database.SpecExtension");
            Object ext = se.getConstructor(ghidra.program.model.listing.Program.class).newInstance(currentProgram);
            se.getMethod("addReplaceCompilerSpecExtension", String.class, ghidra.util.task.TaskMonitor.class)
                    .invoke(ext, conventionXml(name), monitor);
        }
        int set = 0, kept = 0, reset = 0;
        java.util.Set<Address> want = new java.util.HashSet<>();
        for (JsonElement e : list) want.add(addr(e.getAsString()));
        want.removeAll(skip);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (name.equals(f.getCallingConventionName()) && !want.contains(f.getEntryPoint())) {
                f.setCallingConvention("__fastcall");
                reset++;
            }
        }
        if (reset > 0) println("ApplyFacts: " + reset + " functions no longer listed for " + name + ": __fastcall");
        for (Address a : want) {
            Function f = getFunctionAt(a);
            if (f == null || f.isExternal() || f.isThunk() || f.hasCustomVariableStorage()) continue;
            if (name.equals(f.getCallingConventionName())) {
                kept++;
                continue;
            }
            f.setCallingConvention(name);
            set++;
        }
        println("ApplyFacts: " + name + " given to " + set + " functions (already " + kept + ")");
    }

    // switches.json (tools/switches.py): jump tables read off the instructions, written as a
    // jump-table override where Ghidra has no flow out of the jump (the decompiler then followed
    // it into nothing: FUN_1406303d0, "Flow exceeded maximum allowable instructions"). A function
    // Ghidra made at a case is removed: it is the switch's own code
    private void applySwitches(JsonObject root) throws Exception {
        int set = 0, resolved = 0, missing = 0, removed = 0;
        Class<?> jt = Function.class.getClassLoader().loadClass("ghidra.program.model.pcode.JumpTable");
        // (Ghidra 12: JumpTable(Address, ArrayList<Address>, boolean override, int format); older
        // versions take the first three)
        java.lang.reflect.Constructor<?> make = null;
        for (java.lang.reflect.Constructor<?> c : jt.getConstructors()) {
            Class<?>[] ps = c.getParameterTypes();
            if ((ps.length == 3 || (ps.length == 4 && ps[3] == int.class)) && ps[0] == Address.class
                    && ps[1].isAssignableFrom(ArrayList.class) && ps[2] == boolean.class) {
                make = c;
            }
        }
        if (make == null) {
            StringBuilder have = new StringBuilder();
            for (java.lang.reflect.Constructor<?> c : jt.getConstructors()) have.append(c).append("; ");
            println("ApplyFacts: no JumpTable(Address, List, boolean) constructor: " + have);
            return;
        }
        java.lang.reflect.Method write = jt.getMethod("writeOverride", Function.class);
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("jumps").entrySet()) {
            Address j = addr(e.getKey());
            Instruction insn = getInstructionAt(j);
            Function f = getFunctionContaining(j);
            if (insn == null || f == null) {
                missing++;
                continue;
            }
            boolean flows = false;
            for (ghidra.program.model.symbol.Reference r : insn.getReferencesFrom()) {
                if (r.getReferenceType().isJump() || r.getReferenceType().isComputed()) flows = true;
            }
            // (and where Ghidra's table is shorter than the one the instructions give: it truncated
            // it, "Sanity check requires truncation of jumptable", and FUN_1419c3450 ran on into
            // the bytes after it as code)
            // (or a different one: FUN_1419c3450's two-level table, a case of Ghidra's own running
            // into data, "Bad instruction - Truncating control flow here")
            java.util.Set<Address> have = new java.util.HashSet<>();
            for (ghidra.program.model.symbol.Reference r : insn.getReferencesFrom()) {
                if (r.getReferenceType().isJump() || r.getReferenceType().isComputed()) have.add(r.getToAddress());
            }
            for (Address fl : insn.getFlows()) have.add(fl);
            java.util.Set<Address> ours = new java.util.HashSet<>();
            for (JsonElement t : e.getValue().getAsJsonArray()) ours.add(addr(t.getAsString()));
            if (have.equals(ours)) {
                resolved++;
                continue;
            }
            // (Ghidra's references that are not cases go: they are what the decompiler followed)
            for (ghidra.program.model.symbol.Reference r : insn.getReferencesFrom()) {
                if ((r.getReferenceType().isJump() || r.getReferenceType().isComputed()) && !ours.contains(r.getToAddress())) {
                    currentProgram.getReferenceManager().delete(r);
                }
            }
            ArrayList<Address> dests = new ArrayList<>();
            for (JsonElement t : e.getValue().getAsJsonArray()) {
                Address d = addr(t.getAsString());
                Function at = getFunctionAt(d);
                if (at != null && !at.equals(f)) {
                    currentProgram.getFunctionManager().removeFunction(d);
                    removed++;
                }
                if (getInstructionAt(d) == null) disassemble(d);
                currentProgram.getReferenceManager().addMemoryReference(j, d,
                        ghidra.program.model.symbol.RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
                dests.add(d);
            }
            Object table = make.getParameterCount() == 4 ? make.newInstance(j, dests, true, 0) : make.newInstance(j, dests, true);
            write.invoke(table, f);
            CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
            set++;
        }
        println("ApplyFacts: jump tables written " + set + " (Ghidra had " + resolved + "), functions at cases removed "
                + removed + ", not found " + missing);
    }

    // Win64's place for position i (0-based) of a kind: rcx/rdx/r8/r9 as wide as the type, the
    // low lane of xmm0-3 for a float or double, all of it for a vector, the stack from entry +0x28
    private ghidra.program.model.listing.VariableStorage paramStorage(int i, String kind, DataType dt) throws Exception {
        if (i >= 4) {
            return new ghidra.program.model.listing.VariableStorage(currentProgram, 0x28 + 8 * (i - 4), dt.getLength());
        }
        String reg;
        switch (kind) {
            case "f": case "x": reg = "XMM" + i + "_Da"; break;
            case "d": reg = "XMM" + i + "_Qa"; break;
            case "v": reg = "XMM" + i; break;
            default: {
                String[][] names = { { "CL", "CX", "ECX", "RCX" }, { "DL", "DX", "EDX", "RDX" },
                        { "R8B", "R8W", "R8D", "R8" }, { "R9B", "R9W", "R9D", "R9" } };
                int w = dt.getLength();
                reg = names[i][w <= 1 ? 0 : w <= 2 ? 1 : w <= 4 ? 2 : 3];
            }
        }
        return new ghidra.program.model.listing.VariableStorage(currentProgram, currentProgram.getRegister(reg));
    }

    private ghidra.program.model.listing.VariableStorage returnStorage(String kind, DataType dt) throws Exception {
        if (kind == null || dt instanceof ghidra.program.model.data.VoidDataType) {
            return ghidra.program.model.listing.VariableStorage.VOID_STORAGE;
        }
        String reg;
        switch (kind) {
            case "f": case "x": reg = "XMM0_Da"; break;
            case "d": reg = "XMM0_Qa"; break;
            case "v": reg = "XMM0"; break;
            default: {
                int w = dt.getLength();
                reg = w <= 1 ? "AL" : w <= 2 ? "AX" : w <= 4 ? "EAX" : "RAX";
            }
        }
        return new ghidra.program.model.listing.VariableStorage(currentProgram, currentProgram.getRegister(reg));
    }

    // callsites.json (tools/protos.py): each indirect call's arguments as the caller sets them up,
    // written as a call-site signature override. Without one the decompiler guesses from the
    // registers it sees set and drops what it cannot tie to the call: cross_ssl's start lost the
    // logger in r8 at its factory Initialize call (0x141f2ee98), and the SChannel setup then logged
    // through a garbage pointer. One signature per distinct shape, shared by every site.
    private void applyCallsites(JsonObject root) throws Exception {
        Map<String, FunctionDefinitionDataType> shapes = new HashMap<>();
        int written = 0, missing = 0, failed = 0;
        // HighFunctionDBUtil through Ghidra's own class loader: the script bundle's manifest
        // did not import its package (ghidra.program.model.pcode), and the class was not found
        // however it was named, aborting the session before its exports (2026-10-16)
        java.lang.reflect.Method writeOverride = Function.class.getClassLoader()
                .loadClass("ghidra.program.model.pcode.HighFunctionDBUtil")
                .getMethod("writeOverride", Function.class, Address.class,
                        ghidra.program.model.listing.FunctionSignature.class);
        String firstError = null;
        // every call-site override from earlier sessions goes first: writeOverride adds a symbol
        // per signature (`override::prt_1417dbac9_<hash>`) and removes none, so a call kept every
        // override it was ever given and the decompiler went on using an old one (the float
        // return written for 0x1417dbac9 beside two undefined8 ones, 2026-10-16)
        List<ghidra.program.model.symbol.Symbol> stale = new ArrayList<>();
        for (ghidra.program.model.symbol.Symbol s : currentProgram.getSymbolTable().getAllSymbols(false)) {
            Namespace p = s.getParentNamespace();
            if (p != null && "override".equals(p.getName()) && s.getName().startsWith("prt_")) stale.add(s);
        }
        for (ghidra.program.model.symbol.Symbol s : stale) s.delete();
        println("ApplyFacts: earlier call-site overrides removed " + stale.size());
        // an indirect tail jump (`jmp [rax + 0x48]`) is a call that returns: the decompiler then
        // shows it as one and takes its call-site signature, which it ignores on a jump. HMAC's
        // update wrapper FUN_1420bd740 measures its string into r8 and jumps on through a table;
        // as a jump its call showed no arguments and the length was lost (2026-10-20)
        int jumpsMarked = 0;
        if (root.has("jumps")) {
            java.util.Set<Function> refit = new java.util.HashSet<>();
            for (JsonElement j : root.getAsJsonArray("jumps")) {
                Instruction insn = getInstructionAt(addr(j.getAsString()));
                if (insn == null || !insn.getFlowType().isJump()) continue;
                if (insn.getFlowOverride() != FlowOverride.CALL_RETURN) {
                    insn.setFlowOverride(FlowOverride.CALL_RETURN);
                    Function c = getFunctionContaining(insn.getAddress());
                    if (c != null) refit.add(c);
                }
                jumpsMarked++;
            }
            for (Function c : refit) CreateFunctionCmd.fixupFunctionBody(currentProgram, c, monitor);
        }
        println("ApplyFacts: indirect tail jumps made calls that return " + jumpsMarked);
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("calls").entrySet()) {
            Address at = addr(e.getKey());
            Function f = getFunctionContaining(at);
            if (f == null) {
                missing++;
                continue;
            }
            // (a call through a constant slot takes its callee's prototype: constantCallSlots32)
            if (constSlotCalls.contains(at)) continue;
            JsonArray args = e.getValue().getAsJsonArray();
            StringBuilder key = new StringBuilder();
            for (JsonElement a : args) {
                JsonArray p = a.getAsJsonArray();
                key.append(p.get(0).getAsString()).append(p.get(1).getAsInt());
            }
            // the convention, where the facts give one (x86, protos32.py: __thiscall passes its
            // first argument in ecx)
            JsonObject ccs = root.has("cc") ? root.getAsJsonObject("cc") : null;
            String cc = ccs != null && ccs.has(e.getKey()) ? ccs.get(e.getKey()).getAsString() : null;
            if (cc != null) key.append("_").append(cc.replace("__", ""));
            // a direct call (to a variadic function, tools/protos.py) returns what its callee
            // does; an indirect one a register's worth
            DataType ret = Undefined.getUndefinedDataType(8);
            // (on x86, eax whole: an undefined return is unlocked, and the decompiler sized it by
            // the caller's first use, `test al, al` making a pointer result CONCAT31(extraout_var,
            // uVar1) in F_00405f60's allocator calls, 2026-10-23)
            if (currentProgram.getDefaultPointerSize() == 4) ret = ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            // an indirect call's result as its caller reads it (a float through `call [rax +
            // 0x68]` was `extraout_XMM0_Da` against undefined8: 46 stubs, 2026-10-16)
            JsonObject rets = root.has("rets") ? root.getAsJsonObject("rets") : null;
            if (rets != null && rets.has(e.getKey())) {
                JsonArray r = rets.getAsJsonArray(e.getKey());
                ret = returnType(r.get(0).getAsString(), r.get(1).getAsInt(), null);
                key.append("_r").append(r.get(0).getAsString()).append(r.get(1).getAsInt());
            }
            Instruction insn = getInstructionAt(at);
            Address[] flows = insn != null ? insn.getFlows() : null;
            // (a call through a pointer whose target Ghidra knows, the CFG guard's `call [rip +
            // __guard_dispatch_icall_fptr]`, has a flow to that routine: what the caller reads
            // of the real target's result is the return, not the guard routine's void)
            if (flows != null && flows.length == 1 && (rets == null || !rets.has(e.getKey()))) {
                Function callee = getFunctionAt(flows[0]);
                // (on x86 not an undefined one, which is unlocked: the vtable F_00405f60 loads as
                // a constant on one path gave `call eax` a target whose return Ghidra never sized)
                if (callee != null && !(currentProgram.getDefaultPointerSize() == 4
                        && Undefined.isUndefined(callee.getReturnType()))) {
                    ret = callee.getReturnType();
                    key.append("_r").append(ret.getName().replaceAll("\\W", ""));
                }
            }
            // (on x86 the return in the name too: a shape's data type stays in the program from
            // session to session, and one made again under its old name kept its old return)
            if (currentProgram.getDefaultPointerSize() == 4 && key.indexOf("_r") < 0) {
                key.append("_r").append(ret.getName().replaceAll("\\W", ""));
            }
            FunctionDefinitionDataType sig = shapes.get(key.toString());
            if (sig == null) {
                sig = new FunctionDefinitionDataType("icall_" + (key.length() == 0 ? "void" : key.toString()));
                List<ghidra.program.model.data.ParameterDefinition> defs = new ArrayList<>();
                int i = 0;
                for (JsonElement a : args) {
                    JsonArray p = a.getAsJsonArray();
                    defs.add(new ghidra.program.model.data.ParameterDefinitionImpl("param_" + (++i),
                            paramType(p.get(0).getAsString(), p.get(1).getAsInt(), null), null));
                }
                sig.setArguments(defs.toArray(new ghidra.program.model.data.ParameterDefinition[0]));
                sig.setReturnType(ret);
                if (cc != null) sig.setCallingConvention(cc);
                shapes.put(key.toString(), sig);
            }
            try {
                writeOverride.invoke(null, f, at, sig);
                written++;
            } catch (Exception ex) {
                if (firstError == null) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    firstError = at + ": " + cause;
                }
                failed++;
            }
        }
        println("ApplyFacts: indirect call signatures written " + written + " (" + shapes.size() + " shapes), "
                + "outside any function " + missing + ", failed " + failed
                + (firstError != null ? " (first: " + firstError + ")" : ""));
    }

    // a result's type: Ghidra's when it is as wide as the callers read and of the same kind, else
    // one of that width (a byte read of an undefined8 result was `in_RAX & 0xffffffffffffff00`)
    private DataType returnType(String kind, int size, DataType have) {
        boolean haveFloat = have instanceof ghidra.program.model.data.AbstractFloatDataType;
        switch (kind) {
            case "f":
                return haveFloat && have.getLength() == 4 ? have : ghidra.program.model.data.FloatDataType.dataType;
            case "d":
                return haveFloat && have.getLength() == 8 ? have : ghidra.program.model.data.DoubleDataType.dataType;
            case "x":
                return haveFloat ? have : ghidra.program.model.data.FloatDataType.dataType;
            case "v":
                // a vector result (xmm0 whole: a sincos's two lanes): 16 bytes
                return new ArrayDataType(Undefined.getUndefinedDataType(1), 16, 1);
            default:
                if (have != null && !haveFloat && have.getLength() == size && plain(have)) return have;
                return Undefined.getUndefinedDataType(Math.min(8, Math.max(1, size)));
        }
    }

    // intparams.json (tools/intparams.py): integer positions the decompiler typed float of its
    // own accord, from a spill or a whole-register move, though the code reads them as integers.
    // An undefined type left it free to do so again; these get a concrete unsigned one. The
    // UnitData reader FUN_1425019e0's flags came out `float param_4`, tested as `(uint)param_4 &
    // 1`, a conversion: the owner-only GUID was skipped, every later field read 2 bytes early, and
    // the player's class was 0 (2026-10-21)
    private final Map<Address, Set<Integer>> intParams = new HashMap<>();

    // and the home slot a pinned register parameter is spilled to (entry rsp + 8 * position, the
    // first four): typed float there too, `local_res20[0] = (float)param_4;` and every test of the
    // flags went through `(uint)local_res20[0]`, a conversion again (FUN_1425019e0, 2026-10-21)
    private void applyIntParamHomes(JsonObject functions) {
        int made = 0;
        for (Map.Entry<Address, Set<Integer>> e : intParams.entrySet()) {
            Function f = getFunctionAt(e.getKey());
            String key = "0x" + Long.toHexString(e.getKey().getOffset());
            JsonObject o = functions.has(key) ? functions.getAsJsonObject(key) : null;
            if (f == null || o == null) continue;
            JsonArray want = o.getAsJsonArray("params");
            ghidra.program.model.listing.StackFrame sf = f.getStackFrame();
            for (int pos : e.getValue()) {
                if (pos > 4 || pos > want.size()) continue;
                int size = want.get(pos - 1).getAsJsonArray().get(1).getAsInt();
                // (none in the frame yet: the decompiler makes its own and types it from the
                // moves, so one is made; an integer one already there is left alone)
                Variable v = sf.getVariableContaining(8 * pos);
                if (v != null && v.getStackOffset() != 8 * pos) {
                    println("ApplyFacts: home slot of " + f.getName() + " param " + pos + " inside " + v.getName()
                            + " at " + v.getStackOffset() + ", left");
                    continue;
                }
                String name = v != null ? v.getName() : String.format("local_res%x", 8 * pos);
                // (the whole 8-byte slot: a 4-byte variable there was ignored, the decompiler saw
                // the slot accessed whole and made its own `float local_res20 [2]` over it)
                DataType slot = size >= 8 ? concreteInt(8) : new ArrayDataType(concreteInt(size), 8 / Math.max(1, size), size);
                if (v != null && v.getDataType().isEquivalent(slot)) continue;
                try {
                    if (v != null) sf.clearVariable(8 * pos);
                    sf.createVariable(name, 8 * pos, slot, SourceType.USER_DEFINED);
                    made++;
                    println("ApplyFacts: home slot of " + f.getName() + " param " + pos + " (" + name + ") "
                            + (v != null ? "retyped from " + v.getDataType().getName() : "made") + " " + slot.getName());
                } catch (Exception ex) {
                    println("ApplyFacts: home slot of " + f.getName() + " param " + pos + " failed: " + ex.getMessage());
                }
            }
        }
        println("ApplyFacts: integer parameters' home slots retyped " + made);
    }

    private static DataType concreteInt(int size) {
        switch (Math.min(8, Math.max(1, size))) {
            case 1: return ghidra.program.model.data.ByteDataType.dataType;
            case 2: return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case 4: return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            default: return ghidra.program.model.data.UnsignedLongLongDataType.dataType;
        }
    }

    // a position's type: Ghidra's when it is of the kind the instructions read, else one of the
    // width read ("-": nothing reads it, but a later position is used, so it is still passed)
    private DataType paramType(String kind, int size, DataType have) {
        boolean haveFloat = have instanceof ghidra.program.model.data.AbstractFloatDataType;
        switch (kind) {
            case "f":
                return haveFloat && have.getLength() == 4 ? have : ghidra.program.model.data.FloatDataType.dataType;
            case "d":
                return haveFloat && have.getLength() == 8 ? have : ghidra.program.model.data.DoubleDataType.dataType;
            case "n":
                // an integer whose slot the function reuses for a float (protos32.py): an integer
                // type, or the decompiler takes the float's for the parameter
                return concreteInt(size);
            case "x":
                // an xmm argument only ever moved whole: float or double is not in the code
                return haveFloat ? have : ghidra.program.model.data.FloatDataType.dataType;
            case "v":
                // four lanes in the register (packed arithmetic reads them): 16 bytes
                return new ArrayDataType(Undefined.getUndefinedDataType(1), 16, 1);
            case "i":
                // Ghidra's only when it is as wide as the code reads: an int kept for a register
                // read whole made the decompiler fill the upper half with a register it lost
                // track of (`CONCAT44(in_register_00000014, param_2)`), 591 stubs on 2026-10-16
                // Nor wider than it: a uint kept for a byte the code reads (`movzx edi, r8b`)
                // made every caller that sets only r8b pass `CONCAT31((int3)(in_R8D >> 8), 1)`
                // And only a type C knows: a class or array pointer (`MRECmpImpl *this`, an FID
                // library signature's; `undefined1 (*param_1) [16]`, Ghidra's for a pointer SSE
                // reads through) left `->` and type names the translator cannot spell (~40
                // stubs, 2026-10-16)
                if (have != null && !haveFloat && have.getLength() == Math.min(8, size) && plain(have)) {
                    return have;
                }
                // (one stored as a float: an undefined type of its width would let the decompiler
                // infer the float again, see intParams)
                if (haveFloat) return concreteInt(size);
                return Undefined.getUndefinedDataType(Math.min(8, Math.max(1, size)));
            default:
                if (have != null && have.getLength() > 0 && have.getLength() <= 8 && plain(have)) return have;
                return Undefined.getUndefinedDataType(8);
        }
    }

    // Every function name a call can be read back by: a name more than one function has (FID's
    // `FID_conflict:fallbackMethod` on three, library copies the image links twice) gets its
    // address appended, so a decompiled call says which one (tools/translate.py resolves a
    // `name_<address>` to that address; by the name alone 20 calls did not link, 2026-10-16)
    private void uniqueNames() throws Exception {
        Map<String, List<Function>> byName = new HashMap<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal() || f.getName().startsWith("FUN_")) continue;
            byName.computeIfAbsent(f.getName(true), k -> new ArrayList<>()).add(f);
        }
        int renamed = 0;
        for (List<Function> fs : byName.values()) {
            if (fs.size() < 2) continue;
            for (Function f : fs) {
                String suffix = "_" + f.getEntryPoint().toString();
                if (f.getName().endsWith(suffix)) continue;
                f.setName(f.getName().replace(':', '_') + suffix, SourceType.IMPORTED);
                renamed++;
            }
        }
        println("ApplyFacts: functions sharing a name made unique by address " + renamed);
        uniqueDataNames();
    }

    // And data: a class with two bases has two vftables, both `Item::vftable` to the RTTI
    // analyzer, and the C names only one. Item's constructor stored the Named one for both and
    // a call through the Valued base ran Named's slots (rhtest cpp-O2, 2026-10-24)
    private void uniqueDataNames() throws Exception {
        Map<String, List<ghidra.program.model.symbol.Symbol>> byName = new HashMap<>();
        for (ghidra.program.model.symbol.Symbol s : symbols.getAllSymbols(false)) {
            if (s.getSymbolType() != ghidra.program.model.symbol.SymbolType.LABEL || s.isExternal()
                    || s.getSource() == SourceType.DEFAULT || !s.isPrimary()
                    || getFunctionAt(s.getAddress()) != null) continue;
            byName.computeIfAbsent(s.getName(true), k -> new ArrayList<>()).add(s);
        }
        int renamed = 0;
        for (List<ghidra.program.model.symbol.Symbol> ss : byName.values()) {
            if (ss.size() < 2) continue;
            for (ghidra.program.model.symbol.Symbol s : ss) {
                String suffix = "_" + s.getAddress().toString();
                if (s.getName().endsWith(suffix)) continue;
                s.setName(s.getName() + suffix, SourceType.ANALYSIS);
                renamed++;
            }
        }
        println("ApplyFacts: data labels sharing a name made unique by address " + renamed);
    }

    // globalptrs.json: .data globals the code dereferences after loading them whole. Typed
    // `undefined *` where nothing typed them (no data, or an undefined of up to 8 bytes): the
    // decompiler then casts each access through one to its width, where it printed `*DAT_x` of a
    // bare undefined8 that the translator cannot spell (13 stubs, 2026-10-16)
    private void applyGlobalPtrs(JsonObject root) throws Exception {
        int set = 0, typed = 0, inside = 0;
        DataType bytePtr = new PointerDataType(Undefined.getUndefinedDataType(1));
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("globals").entrySet()) {
            Address g = addr(e.getKey());
            Data d = getDataAt(g);
            if (d == null) {
                Data over = currentProgram.getListing().getDataContaining(g);
                if (over != null) {
                    inside++;
                    continue;
                }
                if (currentProgram.getListing().getInstructionContaining(g) != null) {
                    inside++;
                    continue;
                }
            } else {
                DataType t = d.getDataType();
                boolean untyped = t instanceof ghidra.program.model.data.Undefined
                        || t instanceof ghidra.program.model.data.DefaultDataType;
                if (!untyped || d.getLength() > 8) {
                    typed++;
                    continue;
                }
            }
            // (and nothing typed starts inside the 8 bytes it takes)
            boolean clash = false;
            for (int k = 1; k < 8 && !clash; k++) {
                Data dk = getDataAt(g.add(k));
                clash = dk != null && !(dk.getDataType() instanceof ghidra.program.model.data.Undefined
                        || dk.getDataType() instanceof ghidra.program.model.data.DefaultDataType);
            }
            if (clash) {
                inside++;
                continue;
            }
            clearListing(g, g.add(7));
            createData(g, bytePtr);
            set++;
        }
        println("ApplyFacts: global pointers typed " + set + ", already typed " + typed + ", inside other data " + inside);
    }

    // an integer, or a pointer to one (or to nothing, or to such a pointer): what the decompiled
    // C can spell without the program's own types
    private static boolean plain(DataType t) {
        while (t instanceof ghidra.program.model.data.TypeDef) {
            t = ((ghidra.program.model.data.TypeDef) t).getBaseDataType();
        }
        if (t instanceof Pointer) {
            DataType to = ((Pointer) t).getDataType();
            return to == null || to instanceof ghidra.program.model.data.VoidDataType || plain(to)
                    || to instanceof ghidra.program.model.data.AbstractFloatDataType;
        }
        return t instanceof ghidra.program.model.data.AbstractIntegerDataType
                || t instanceof ghidra.program.model.data.Undefined
                || t instanceof ghidra.program.model.data.DefaultDataType
                || t instanceof ghidra.program.model.data.BooleanDataType
                || t instanceof ghidra.program.model.data.CharDataType;
    }

    // retcheck.json: functions carrying the anti-tamper return-address check.
    private void applyRetcheck(JsonObject root) throws Exception {
        int stale = dropStaleTags("tamper:retcheck", root.getAsJsonObject("functions").keySet());
        if (stale > 0) println("ApplyFacts: dropped " + stale + " stale tamper:retcheck tags");
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) continue;
            f.addTag("tamper:retcheck");
            Address tail = addr(e.getValue().getAsString());
            setEOLComment(tail, "anti-tamper return-address check starts here: protection, not game logic");
            tagged++;
        }
        if (root.has("junk_jumps")) applyJunkJumps(root.getAsJsonObject("junk_jumps"),
                root.has("junk_ends") ? root.getAsJsonObject("junk_ends") : new JsonObject());
        if (root.has("checks")) applyChecks(root.getAsJsonObject("checks"));
    }

    // A jump an earlier session made unconditional that tools/retcheck.py no longer lists: its
    // bytes back as the file has them, and the code after it decoded again with flow. Patched,
    // it took the program's bytes with it, and the junk cleared after it was real code: the
    // `je` past Lua::SendChatMessage's lua_isstring test went straight to the usage error, the
    // 40 KB of the handler after it left undefined bytes, and the function was stubbed as one
    // the decompiler lost calls in (2026-10-18). Only that shape is undone, an original
    // conditional jump (`0f 8x`, `7x`) now `e9`/`eb`: the skipped checks and the __chkstk nops are
    // patches of other bytes and stay.
    private void revertStaleJunkJumps(JsonObject jumps) throws Exception {
        java.util.Set<Address> current = new java.util.HashSet<>();
        for (String k : jumps.keySet()) current.add(addr(k));
        ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
        ghidra.program.model.mem.MemoryBlock text = mem.getBlock(".text");
        if (text == null) return;
        int reverted = 0, regrown = 0;
        java.util.Set<Function> touched = new java.util.HashSet<>();
        for (ghidra.program.model.mem.MemoryBlockSourceInfo info : text.getSourceInfos()) {
            if (info.getFileBytes().isEmpty()) continue;
            // (through reflection: the script bundle does not import the db package, as for the
            // convention table in reclaimConventionSlots)
            Object fb = info.getFileBytes().get();
            java.lang.reflect.Method original = fb.getClass().getMethod("getOriginalBytes", long.class, byte[].class);
            Address lo = info.getMinAddress();
            long size = info.getLength();
            int chunk = 1 << 20;
            for (long off = 0; off < size; off += chunk) {
                int n = (int) Math.min(chunk + 8, size - off);
                byte[] now = new byte[n], orig = new byte[n];
                mem.getBytes(lo.add(off), now);
                original.invoke(fb, info.getFileBytesOffset() + off, orig);
                for (int i = 0; i < Math.min(chunk, n); i++) {
                    if (now[i] == orig[i]) continue;
                    int o0 = orig[i] & 0xff, n0 = now[i] & 0xff;
                    int len;
                    if (o0 == 0x0f && i + 1 < n && (orig[i + 1] & 0xf0) == 0x80 && n0 == 0xe9) len = 6;
                    else if ((o0 & 0xf0) == 0x70 && n0 == 0xeb) len = 2;
                    else continue;
                    Address j = lo.add(off + i);
                    i += len - 1;
                    if (current.contains(j)) continue;
                    Function f = getFunctionContaining(j);
                    // (code only where code runs into it: a jump table's entry taken for a jump,
                    // FUN_1417354c0's `0x73`, gets its byte back and stays data)
                    Instruction prev = getInstructionContaining(j.subtract(1));
                    boolean code = prev != null && prev.getMaxAddress().equals(j.subtract(1)) && prev.getFlowType().hasFallthrough();
                    clearListing(j, j.add(len - 1));
                    byte[] back = java.util.Arrays.copyOfRange(orig, (int) (j.subtract(lo) - off), (int) (j.subtract(lo) - off) + len);
                    mem.setBytes(j, back);
                    reverted++;
                    if (!code) continue;
                    DisassembleCommand cmd = new DisassembleCommand(j, null, true);
                    cmd.applyTo(currentProgram, monitor);
                    Instruction insn = getInstructionAt(j);
                    if (insn != null) {
                        insn.setFlowOverride(FlowOverride.NONE);
                        // (and its fall-through, which the old patch had cleared as junk)
                        Address ft = insn.getFallThrough();
                        if (ft != null && getInstructionAt(ft) == null) {
                            new DisassembleCommand(ft, null, true).applyTo(currentProgram, monitor);
                            if (getInstructionAt(ft) != null) regrown++;
                        }
                    }
                    if (f != null) touched.add(f);
                }
            }
        }
        for (Function f : touched) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        println("ApplyFacts: stale jumps over junk reverted " + reverted + " (" + regrown
                + " fall-throughs decoded again), in " + touched.size() + " functions");
    }

    // Each check skipped (tools/retcheck.py): its start, the 7-byte load of the range base,
    // becomes `jmp T; nop; nop`, T being where the function's code resumes once the return
    // address passes. The check is then unreachable and the decompiler leaves it out; stripped
    // from the decompiled text instead, 143 functions in shapes the pattern did not know were
    // stubbed (2026-10-16). Ghidra's copy only, as for the junk jumps; done already, left alone.
    private void applyChecks(JsonObject checks) throws Exception {
        int set = 0, done = 0, missing = 0;
        for (Map.Entry<String, JsonElement> e : checks.entrySet()) {
            Address s = addr(e.getKey());
            Address t = addr(e.getValue().getAsString());
            Instruction insn = getInstructionAt(s);
            // (Ghidra's decode out of step at the start, or none there at all: a check that a jump
            // over junk lands on, FUN_1424db710's at 0x1424dc570 among six left unpatched,
            // 2026-10-19. The bytes say what is there: the 7-byte `mov reg, [rip + base]`, every code
            // unit across them cleared, then decoded alone)
            if (insn == null || insn.getLength() != 7) {
                byte[] b7 = new byte[7];
                currentProgram.getMemory().getBytes(s, b7);
                boolean load = ((b7[0] & 0xfb) == 0x48) && (b7[1] & 0xff) == 0x8b && (b7[2] & 0xc7) == 0x05;
                if (load) {
                    Address end = s.add(6);
                    CodeUnit first = currentProgram.getListing().getCodeUnitContaining(s);
                    CodeUnit last = currentProgram.getListing().getCodeUnitContaining(end);
                    Address lo = first != null && first.getMinAddress().compareTo(s) < 0 ? first.getMinAddress() : s;
                    Address hi = last != null && last.getMaxAddress().compareTo(end) > 0 ? last.getMaxAddress() : end;
                    clearListing(lo, hi);
                    new DisassembleCommand(s, null, false).applyTo(currentProgram, monitor);
                    insn = getInstructionAt(s);
                }
            }
            if (insn == null) {
                missing++;
                continue;
            }
            byte[] code = insn.getBytes();
            if ((code[0] & 0xff) == 0xe9) {
                done++;
                clearDeadCheck(s, t);
                continue;
            }
            if (code.length != 7) {
                missing++;
                continue;
            }
            long rel = t.getOffset() - (s.getOffset() + 5);
            byte[] patched = new byte[] { (byte) 0xe9, (byte) rel, (byte) (rel >> 8), (byte) (rel >> 16),
                    (byte) (rel >> 24), (byte) 0x90, (byte) 0x90 };
            clearListing(s, s.add(6));
            currentProgram.getMemory().setBytes(s, patched);
            new DisassembleCommand(s, null, false).applyTo(currentProgram, monitor);
            if (getInstructionAt(s) == null) {
                missing++;
                continue;
            }
            if (getInstructionAt(t) == null) {
                disassemble(t);
            }
            clearDeadCheck(s, t);
            set++;
        }
        for (Function f : deadCheckFunctions) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        println("ApplyFacts: return-address checks skipped " + set + " (already " + done + "), not patched " + missing
                + "; dead check bodies cleared " + deadCleared + ", kept for a jump into them " + deadKept);
    }

    private int deadCleared, deadKept;
    private final java.util.Set<Function> deadCheckFunctions = new java.util.HashSet<>();

    // A skipped check's own body, from past its start's jump to where the code resumes: dead once
    // the start jumps over it, but still in the listing, and the decompiler decodes every block of
    // a function before it drops the unreachable ones, so the junk in the check's crash path
    // marked the decompilation damaged (CreateFrame's core, FUN_1424db710, warned of an overlap at
    // 0x1424dc1ea in its second check and was kept as protection junk, 2026-10-19). Cleared only
    // when it runs forward to the resumption and nothing outside it jumps in.
    private void clearDeadCheck(Address s, Address t) throws Exception {
        Address lo = s.add(7);
        if (t.compareTo(lo) <= 0 || t.subtract(lo) > 0x4000) return;
        Address hi = t.subtract(1);
        ghidra.program.model.address.AddressSet region = new ghidra.program.model.address.AddressSet(lo, hi);
        ghidra.program.model.symbol.ReferenceManager rm = currentProgram.getReferenceManager();
        ghidra.program.model.address.AddressIterator dests = rm.getReferenceDestinationIterator(region, true);
        while (dests.hasNext()) {
            Address d = dests.next();
            for (ghidra.program.model.symbol.Reference r : rm.getReferencesTo(d)) {
                Address from = r.getFromAddress();
                if (from.compareTo(s) < 0 || from.compareTo(hi) > 0) {
                    deadKept++;
                    return;
                }
            }
        }
        Function f = getFunctionContaining(s);
        CodeUnit across = currentProgram.getListing().getCodeUnitContaining(hi);
        if (across != null && across.getMaxAddress().compareTo(hi) > 0) hi = across.getMinAddress().subtract(1);
        if (hi.compareTo(lo) < 0) return;
        clearListing(lo, hi);
        if (f != null) deadCheckFunctions.add(f);
        deadCleared++;
    }

    // The check's conditional jumps over junk (tools/retcheck.py): the fall-through bytes are no
    // code, and decoded they run straight across the jump's own target, so the decompiler saw
    // overlapping instructions and lost the function (155 stubs, 2026-10-16). Each jump is made
    // unconditional (a flow override), the junk is cleared, and the target disassembled.
    private void applyJunkJumps(JsonObject jumps, JsonObject ends) throws Exception {
        revertStaleJunkJumps(jumps);
        int set = 0, missing = 0;
        for (Map.Entry<String, JsonElement> e : jumps.entrySet()) {
            Address j = addr(e.getKey());
            Address t = addr(e.getValue().getAsString());
            Instruction insn = getInstructionAt(j);
            if (insn == null) {
                // Ghidra's own decode went through the junk and is out of step here: whatever
                // covers the jump goes, and the jump is decoded where it starts
                CodeUnit over = currentProgram.getListing().getCodeUnitContaining(j);
                if (over != null) {
                    clearListing(over.getMinAddress(), over.getMaxAddress());
                }
                CodeUnit next = currentProgram.getListing().getCodeUnitContaining(j.add(1));
                if (next != null && next.getMinAddress().compareTo(j) > 0) {
                    clearListing(next.getMinAddress(), next.getMaxAddress());
                }
                // the jump alone, without following its flow back into the junk
                new DisassembleCommand(j, null, false).applyTo(currentProgram, monitor);
                insn = getInstructionAt(j);
            }
            if (insn == null) {
                missing++;
                continue;
            }
            // The jump made unconditional in the program's bytes: a flow override does not
            // reach a conditional jump (the decompiler still took the fall-through into the junk
            // and reported the overlap, 2026-10-16). `0f 8x rel32` becomes `e9 rel32+1; nop` and
            // `7x rel8` becomes `eb rel8`, to the same target. Ghidra's copy only: the exe on
            // disk, which the Python tools read, keeps its bytes
            byte[] code = insn.getBytes();
            byte[] patched = null;
            if (code.length == 6 && (code[0] & 0xff) == 0x0f && (code[1] & 0xf0) == 0x80) {
                int rel = (code[2] & 0xff) | (code[3] & 0xff) << 8 | (code[4] & 0xff) << 16 | (code[5] & 0xff) << 24;
                rel += 1;
                patched = new byte[] { (byte) 0xe9, (byte) rel, (byte) (rel >> 8), (byte) (rel >> 16),
                        (byte) (rel >> 24), (byte) 0x90 };
            } else if (code.length == 2 && (code[0] & 0xf0) == 0x70) {
                patched = new byte[] { (byte) 0xeb, code[1] };
            }
            if (patched != null) {
                clearListing(j, j.add(code.length - 1));
                currentProgram.getMemory().setBytes(j, patched);
                new DisassembleCommand(j, null, false).applyTo(currentProgram, monitor);
                insn = getInstructionAt(j);
                if (insn == null) {
                    missing++;
                    continue;
                }
            }
            Address after = j.add(insn.getLength());
            // the junk, and whatever decoded instruction spans its end: up to the target, or
            // (tools/retcheck.py junk_ends) up to the real code the function reaches before it,
            // the block an opposite jump just before goes to (`jl X; jge T` with X between)
            Address stop = ends.has(e.getKey()) ? addr(ends.get(e.getKey()).getAsString()) : t;
            Address end = stop.subtract(1);
            CodeUnit across = currentProgram.getListing().getCodeUnitContaining(stop);
            if (across != null && across.getMinAddress().compareTo(stop) < 0) {
                end = across.getMaxAddress();
            }
            if (after.compareTo(end) <= 0) {
                clearListing(after, end);
            }
            insn.setFlowOverride(FlowOverride.BRANCH);
            if (getInstructionAt(t) == null) {
                disassemble(t);
            }
            if (!stop.equals(t) && getInstructionAt(stop) == null) {
                disassemble(stop);
            }
            set++;
        }
        println("ApplyFacts: jumps over junk made unconditional " + set + ", not an instruction " + missing);
    }

    // Functions that are part of another (tools/pieces.py): a chained .pdata piece, or an entry
    // strictly inside a .pdata function that only its parent jumps to. Each split cost both
    // halves their registers. Removed every session (RemovePieceFunctions.java did it once;
    // analysis made new ones), DEFAULT-named only, and the parents re-flow into the code.
    private void applyPieces(JsonObject root) throws Exception {
        java.util.Set<Address> parents = new java.util.TreeSet<>();
        int removed = 0, failed = 0;
        for (String key : new String[] {"pieces", "interior"}) {
            JsonArray list = root.getAsJsonArray(key);
            if (list == null) continue;
            for (JsonElement el : list) {
                Address a = addr(el.getAsString());
                partOfAnother.add(a);
                Function f = getFunctionAt(a);
                // (and analysis-named: a switch case Ghidra made a function of,
                // `switchD_1416f346c::caseD_6`, is a piece all the same; only user and imported
                // names are kept)
                if (f == null || (f.getSymbol().getSource() != SourceType.DEFAULT
                        && f.getSymbol().getSource() != SourceType.ANALYSIS)) continue;
                try {
                    // (a ConcurrentModificationException inside Ghidra's removal is state-
                    // dependent and clears in a later session: logged, not fatal)
                    removeFunction(f);
                    removed++;
                    Function parent = getFunctionBefore(a);
                    if (parent != null) parents.add(parent.getEntryPoint());
                } catch (java.util.ConcurrentModificationException ex) {
                    failed++;
                }
            }
        }
        for (Address p : parents) {
            Function f = getFunctionAt(p);
            if (f != null) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        }
        println("ApplyFacts: removed " + removed + " functions on pieces and interior entries ("
                + failed + " removals threw), re-flowed " + parents.size() + " parents");
    }

    private void applySrcrefs(JsonObject root) throws Exception {
        int stale = dropStaleTags("src:", root.getAsJsonObject("functions").keySet());
        if (stale > 0) println("ApplyFacts: dropped " + stale + " stale src: tags");
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("functions").entrySet()) {
            // tag existing functions only: creating one here is how 1,787 functions ended
            // up on chained .pdata pieces (see RemovePieceFunctions.java)
            Function f = getFunctionAt(addr(e.getKey()));
            if (f == null) continue;
            JsonArray files = e.getValue().getAsJsonArray();
            StringBuilder sb = new StringBuilder();
            for (JsonElement fe : files) {
                String path = fe.getAsString();
                String file = path.substring(path.lastIndexOf('/') + 1);
                f.addTag("src:" + file);
                if (sb.length() > 0) sb.append('\n');
                sb.append("src: ").append(path);
            }
            String old = f.getComment();
            if (old == null || !old.contains("src: ")) {
                f.setComment(old == null ? sb.toString() : old + "\n" + sb);
            }
            tagged++;
        }
    }
}
