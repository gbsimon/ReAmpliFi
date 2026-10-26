// Headless post-script: exports decompilation, function table, string xrefs, JNI info.
// Usage: -postScript ExportAll.java <outdir>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class ExportAll extends GhidraScript {
    String out;
    Map<String, StringBuilder> groups = new TreeMap<>();
    Map<String, Integer> freeCount = new HashMap<>();
    int freeIdx = 0, freeN = 0;

    String san(String s) { return s.replaceAll("[^A-Za-z0-9_.-]", "_"); }
    String nm(Function f) { return f == null ? "?" : f.getName(true); }

    String mangled(Function f) {
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(f.getEntryPoint())) {
            if (s.getName().startsWith("_Z")) return s.getName();
        }
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(f.getEntryPoint())) {
            String c = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, f.getEntryPoint());
        }
        return "";
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        out = a.length > 0 ? a[0] : "/tmp/ghidra_out";
        new File(out, "decomp").mkdirs();
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        Map<Long,String> strAt = new HashMap<>();
        Map<Long,Set<String>> xr = new HashMap<>();
        for (Data d : listing.getDefinedData(true)) {
            if (!d.hasStringValue() || d.getAddress().toString().contains("::")) continue;
            Object v = d.getValue();
            if (v == null || v.toString().length() < 4) continue;
            strAt.put(d.getAddress().getOffset(), v.toString());
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        List<Function> funcs = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) funcs.add(f);
        println("Functions: " + funcs.size());

        PrintWriter tsv = new PrintWriter(new File(out, "functions.tsv"));
        tsv.println("address\tsize\tname\tnamespace\tis_exported\tcallees\tcallers");
        PrintWriter jni = new PrintWriter(new File(out, "jni_exports.txt"));
        PrintWriter fail = new PrintWriter(new File(out, "decomp_failures.txt"));
        jni.println("## Java_* exports");
        Pattern env = Pattern.compile("\\+\\s*(0x84|0x1c4|0x35c|0x35c|0x1e8|0x1ec)\\)");
        List<String> envHits = new ArrayList<>();
        int ok = 0, bad = 0, n = 0;

        for (Function f : funcs) {
            monitor.checkCancelled();
            n++;
            Set<Function> callers = f.getCallingFunctions(monitor);
            Set<Function> callees = f.getCalledFunctions(monitor);
            String ns = f.getParentNamespace().isGlobal() ? "" : f.getParentNamespace().getName(true);
            boolean exp = f.getSymbol().isExternalEntryPoint() || currentProgram.getSymbolTable().isExternalEntryPoint(f.getEntryPoint());
            tsv.println(f.getEntryPoint() + "\t" + f.getBody().getNumAddresses() + "\t" + f.getName(false) + "\t" + ns + "\t" + exp + "\t" + callees.size() + "\t" + callers.size());
            if (f.getName().startsWith("Java_")) jni.println(f.getEntryPoint() + "\t" + f.getName());

            String code;
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                code = r.getDecompiledFunction().getC();
                ok++;
                ghidra.program.model.pcode.HighFunction hf = r.getHighFunction();
                if (hf != null) {
                    Iterator<ghidra.program.model.pcode.PcodeOpAST> it = hf.getPcodeOps();
                    while (it.hasNext()) {
                        ghidra.program.model.pcode.PcodeOpAST op = it.next();
                        for (ghidra.program.model.pcode.Varnode vn : op.getInputs()) {
                            if (vn == null) continue;
                            if (vn.isConstant() || vn.isAddress()) {
                                long off = vn.getOffset() & 0xffffffffL;
                                if (strAt.containsKey(off)) xr.computeIfAbsent(off, k -> new LinkedHashSet<>()).add(nm(f) + "@" + f.getEntryPoint());
                            }
                        }
                    }
                }
                if (env.matcher(code).find()) envHits.add(f.getEntryPoint() + "\t" + nm(f));
            } else {
                bad++;
                code = "/* DECOMPILE FAILED: " + (r == null ? "null" : r.getErrorMessage()) + " */\n";
                fail.println(f.getEntryPoint() + "\t" + nm(f) + "\t" + (r == null ? "null" : r.getErrorMessage()));
            }
            StringBuilder sb = new StringBuilder();
            sb.append("// ======================================================================\n");
            sb.append("// ADDR: ").append(f.getEntryPoint()).append("  SIZE: ").append(f.getBody().getNumAddresses()).append("\n");
            sb.append("// NAME: ").append(f.getName(true)).append("\n");
            String m = mangled(f);
            if (!m.isEmpty()) sb.append("// MANGLED: ").append(m).append("\n");
            StringBuilder cs = new StringBuilder();
            for (Function c : callers) cs.append(nm(c)).append("@").append(c.getEntryPoint()).append(", ");
            sb.append("// CALLERS: ").append(cs).append("\n");
            sb.append("// ======================================================================\n");
            sb.append(code).append("\n");

            String key;
            if (!ns.isEmpty()) {
                String top = ns;
                key = "class_" + san(top);
                if (key.length() > 120) key = key.substring(0, 120);
            } else {
                int idx = freeN / 200; freeN++;
                key = String.format("free_%04d", idx);
            }
            groups.computeIfAbsent(key, k -> new StringBuilder()).append(sb);
            if (n % 200 == 0) println("decompiled " + n + "/" + funcs.size());
        }
        tsv.close(); fail.close();

        // write decomp files
        PrintWriter idx = new PrintWriter(new File(out, "decomp/INDEX.txt"));
        for (Map.Entry<String, StringBuilder> e : groups.entrySet()) {
            File fl = new File(out, "decomp/" + e.getKey() + ".c");
            try (PrintWriter w = new PrintWriter(fl)) { w.print(e.getValue()); }
            idx.println(e.getKey() + ".c\t" + e.getValue().length());
        }
        idx.close();

        // strings + xrefs
        PrintWriter sx = new PrintWriter(new File(out, "strings_xrefs.tsv"));
        sx.println("address\tstring\treferencing_functions");
        Pattern sig = Pattern.compile("^\\(.*\\)\\[?[A-Za-z]?.*$");
        Map<Function, List<String>> strsByFunc = new LinkedHashMap<>();
        List<String[]> sigStrs = new ArrayList<>();
        for (Data d : listing.getDefinedData(true)) {
            if (!d.hasStringValue() || d.getAddress().toString().contains("::")) continue;
            Object v = d.getValue();
            if (v == null) continue;
            String s = v.toString();
            if (s.length() < 4) continue;
            Set<String> fs = new LinkedHashSet<>();
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
            while (ri.hasNext()) {
                Reference ref = ri.next();
                Function rf = fm.getFunctionContaining(ref.getFromAddress());
                if (rf != null) fs.add(nm(rf) + "@" + rf.getEntryPoint());
            }
            Set<String> x2 = xr.get(d.getAddress().getOffset());
            if (x2 != null) fs.addAll(x2);
            for (String q : fs) {
                String an = q.substring(q.lastIndexOf('@') + 1);
                Function rf = fm.getFunctionAt(toAddr("0x" + an));
                if (rf != null) strsByFunc.computeIfAbsent(rf, k -> new ArrayList<>()).add(s);
            }
            String es = s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r");
            sx.println(d.getAddress() + "\t" + es + "\t" + String.join(" | ", fs));
            if (sig.matcher(s).matches() && s.length() < 200) sigStrs.add(new String[]{d.getAddress().toString(), s, String.join(" | ", fs)});
        }
        sx.close();

        // JNI callbacks
        jni.println();
        jni.println("## JNI-signature-like strings (candidate GetMethodID/RegisterNatives args) with referencing functions and the other strings those functions reference");
        for (String[] t : sigStrs) {
            jni.println(t[0] + "\t" + t[1] + "\t<- " + t[2]);
            for (Function rf : strsByFunc.keySet()) {
                if (t[2].contains("@" + rf.getEntryPoint())) {
                    jni.println("    other strings in " + nm(rf) + ": " + strsByFunc.get(rf));
                }
            }
        }
        jni.println();
        jni.println("## Functions with JNIEnv-vtable-style call offsets in decompiled code (0x84 GetMethodID, 0x1c4 GetStaticMethodID, 0x35c RegisterNatives; heuristic)");
        for (String h : envHits) jni.println(h);
        jni.println();
        jni.println("## Imported/external symbols containing JNI/Java/RegisterNatives");
        for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
            String sn = s.getName();
            if (sn.contains("RegisterNatives") || sn.contains("JNI_OnLoad") || sn.contains("GetMethodID")) jni.println(s.getAddress() + "\t" + sn);
        }
        jni.close();

        // data tables near CRC refs
        PrintWriter dt = new PrintWriter(new File(out, "data_tables.txt"));
        Set<Function> crcFuncs = new LinkedHashSet<>();
        for (Function f : funcs) {
            if (f.getName(true).toLowerCase().contains("crc")) crcFuncs.add(f);
        }
        for (Map.Entry<Function, List<String>> e : strsByFunc.entrySet())
            for (String s : e.getValue()) if (s.toLowerCase().contains("crc")) crcFuncs.add(e.getKey());
        Memory mem = currentProgram.getMemory();
        for (Function f : crcFuncs) {
            dt.println("### " + nm(f) + "@" + f.getEntryPoint());
            Set<Address> seen = new LinkedHashSet<>();
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                for (Reference ref : ins.getReferencesFrom()) {
                    Address ta = ref.getToAddress();
                    if (ta.isMemoryAddress() && !ref.getReferenceType().isFlow() && mem.contains(ta)) {
                        MemoryBlock b = mem.getBlock(ta);
                        if (b != null && !b.isExecute() && seen.add(ta)) {
                            byte[] buf = new byte[512];
                            int got = 0;
                            try { got = mem.getBytes(ta, buf); } catch (Exception ex) {}
                            StringBuilder hx = new StringBuilder();
                            for (int i = 0; i < got; i++) { if (i % 16 == 0) hx.append("\n  ").append(String.format("%+d: ", i)); hx.append(String.format("%02x ", buf[i])); }
                            dt.println(" ref " + ta + " (" + b.getName() + ")" + hx);
                        }
                    }
                }
            }
        }
        dt.close();
        println("DONE ok=" + ok + " failed=" + bad);
    }
}
