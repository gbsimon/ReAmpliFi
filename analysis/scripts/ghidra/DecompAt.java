// Headless post-script (read-only use): decompile functions at given addresses, creating
// functions first if Ghidra did not (static helpers reached only via function pointers).
// Args: <outfile> <hexaddr> [<hexaddr> ...]   (Ghidra addresses, e.g. 00110300)
// Also accepts a name: "name:FooBar" decompiles every function with that name.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class DecompAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(a[0]));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (int i = 1; i < a.length; i++) {
            java.util.List<Function> fs = new java.util.ArrayList<>();
            if (a[i].startsWith("name:")) {
                for (Function f : currentProgram.getFunctionManager().getFunctions(true))
                    if (f.getName().equals(a[i].substring(5))) fs.add(f);
            } else {
                Address ad = toAddr(Long.parseLong(a[i], 16));
                Function f = getFunctionAt(ad);
                if (f == null) {
                    disassemble(ad);
                    f = createFunction(ad, null);
                }
                if (f == null) f = getFunctionContaining(ad);
                if (f == null) { pw.println("// FAILED to create function at " + a[i]); continue; }
                fs.add(f);
            }
            for (Function f : fs) {
                pw.println("// ======================================================================");
                pw.println("// ADDR: " + f.getEntryPoint() + "  SIZE: " + f.getBody().getNumAddresses() + "  NAME: " + f.getName(true));
                pw.println("// ======================================================================");
                DecompileResults r = di.decompileFunction(f, 90, monitor);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                    pw.println(r.getDecompiledFunction().getC());
                else pw.println("// decompile failed: " + (r == null ? "null" : r.getErrorMessage()));
            }
        }
        pw.close();
    }
}
