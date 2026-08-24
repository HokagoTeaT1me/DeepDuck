import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportImports extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "imports.json";
        StringBuilder json = new StringBuilder("[");
        SymbolIterator symbols = currentProgram.getSymbolTable().getExternalSymbols();
        boolean first = true;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{")
                .append("\"name\":\"").append(esc(symbol.getName())).append("\",")
                .append("\"address\":null,")
                .append("\"dangerous\":").append(isDangerous(symbol.getName()))
                .append("}");
        }
        json.append("]");
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json.toString());
        }
    }

    private boolean isDangerous(String name) {
        return name.equals("system") || name.equals("popen") || name.equals("strcpy")
            || name.equals("strcat") || name.equals("sprintf") || name.equals("vsprintf")
            || name.equals("gets") || name.equals("scanf") || name.equals("memcpy")
            || name.startsWith("exec");
    }

    private String esc(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

