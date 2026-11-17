package pdfserver;

import org.springframework.boot.SpringApplication;

public class TestPdfserverApplication {

	public static void main(String[] args) {
		SpringApplication.from(PdfserverApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
