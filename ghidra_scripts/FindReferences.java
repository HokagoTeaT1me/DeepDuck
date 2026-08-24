import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindReferences extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "references.json";
        String addressText = args.length > 1 ? args[1] : "";
        Address address = toAddr(addressText);
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(address);
        while (references.hasNext()) {
            Reference reference = references.next();
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{")
                .append("\"from\":\"").append(reference.getFromAddress().toString()).append("\",")
                .append("\"to\":\"").append(reference.getToAddress().toString()).append("\",")
                .append("\"type\":\"").append(reference.getReferenceType().toString()).append("\"")
                .append("}");
        }
        json.append("]");
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json.toString());
        }
    }
}

