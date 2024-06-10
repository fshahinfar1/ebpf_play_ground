/*
 *  Dagger is the driver class of our tool
 */

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Dagger {

    private String input_file_path;

    public static Dagger from_cli_args(String[] args) throws RuntimeException {
        if (args.length < 1) {
            throw new RuntimeException("Not enough arguments");
        }
        Dagger x = new Dagger(args[0]);
        return x;
    }

    public Dagger(String input_path) {
        this.input_file_path = input_path;
    }

    void run() throws RuntimeException {
        if (this.input_file_path == null) {
            throw new RuntimeException("Input file is not specified");
        }
        System.out.println("Input file is ``" + this.input_file_path + "''");
        Path path = Paths.get(this.input_file_path);
        File f = path.toFile();
        if (!f.isFile()) {
            System.err.println("File not found!");
            throw new RuntimeException("File not found");
        }
        if (!f.canRead()) {
            System.err.println("Can not read the file!");
            throw new RuntimeException("Can not read the file!");
        }

        byte[] byte_code;
        try {
            byte_code = Files.readAllBytes(path);
        } catch (IOException e) {
            System.err.println("Failed to read bytecode");
            System.err.println(e.getMessage());
            throw new RuntimeException("Failed to read bytecode");
        } catch (OutOfMemoryError e) {
            System.err.println(e.getMessage());
            throw new RuntimeException("Failed to read bytecode (memory issue)");
        } catch (Exception e) {
            throw new RuntimeException("Something wrong");
        }

        System.out.println("Number of bytes:" + byte_code.length);
        for (byte b: byte_code) {
            System.out.print(String.format("0x%02X ", b));
        }
    } 
}