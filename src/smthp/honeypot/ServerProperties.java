package smthp.honeypot;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;

public class ServerProperties extends Properties {

	private static final long serialVersionUID = -657532018686882985L;

	private static final String FILENAME = "server.properties";

	private ServerProperties() {
		InputStream in = null;
		try {
			File file = new File(FILENAME);
			System.out.println(file.getAbsoluteFile());
			if (file.canRead()) {
				in = new FileInputStream(FILENAME);
			} else {
				in = getClass().getClassLoader().getResourceAsStream(FILENAME);
			}
			if (in != null) {
				this.load(in);

				Enumeration<Object> en = this.keys();
				while (en.hasMoreElements()) {
					String key = (String) en.nextElement();
					System.out.println(key + "=" + this.getProperty(key));
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	private static class C {
		private final static ServerProperties I = new ServerProperties();
	}

	public static ServerProperties getInstance() {
		return C.I;
	}
}
