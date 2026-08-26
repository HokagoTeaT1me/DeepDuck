import java.io.FileWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileFunction extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "decompile.json";
        String target = args.length > 1 ? args[1] : "main";
        int maxChars = args.length > 2 ? Integer.parseInt(args[2]) : 20000;
        Function function = findFunction(target);
        String code = "";
        String address = "";
        if (function != null) {
            address = function.getEntryPoint().toString();
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                code = results.getDecompiledFunction().getC();
                if (code.length() > maxChars) {
                    code = code.substring(0, maxChars);
                }
            }
            decompiler.dispose();
        }
        String json = "{"
            + "\"name\":\"" + esc(target) + "\","
            + "\"address\":\"" + esc(address) + "\","
            + "\"callers\":[],"
            + "\"callees\":[],"
            + "\"strings\":[],"
            + "\"decompiled_code\":\"" + esc(code) + "\""
            + "}";
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json);
        }
    }

    private Function findFunction(String target) {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.getName().equals(target) || function.getEntryPoint().toString().equals(target)) {
                return function;
            }
        }
        return null;
    }

    private String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.toString();
    }
}

