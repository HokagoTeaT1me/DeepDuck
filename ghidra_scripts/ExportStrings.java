import java.io.FileWriter;
import java.util.Iterator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedDataIterator;

public class ExportStrings extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "strings.json";
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        Iterator<Data> iterator = DefinedDataIterator.byDataInstance(
            currentProgram,
            data -> StringDataInstance.getStringDataInstance(data) != null
        );
        while (iterator.hasNext()) {
            Data data = iterator.next();
            StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
            if (instance == null) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{")
                .append("\"address\":\"").append(data.getAddress().toString()).append("\",")
                .append("\"value\":\"").append(esc(instance.getStringValue())).append("\"")
                .append("}");
        }
        json.append("]");
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json.toString());
        }
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
