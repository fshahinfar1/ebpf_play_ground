class Main {
    private static void usage() {
        System.out.println("Usage: ./elven_dagger <Path to eBPF binary>");
    }

	public static void main(String[] args) {
        if (args.length < 1) {
            usage();
            System.exit(1);
        }
        Dagger app = Dagger.from_cli_args(args);
        try {
            app.run();
        } catch (RuntimeException e) {
            System.err.println("Failed to run!");
            System.exit(1);
        }
    }
}
