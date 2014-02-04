package smthp.honeypot.smtp;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import smthp.honeypot.ServerProperties;


public class Smtp implements Runnable {

	private final Socket socket;
	private final String SERVER_NAME = ServerProperties.getInstance()
			.getProperty("smtp.server.name", "mailserver");
	private final String SERVER_BANNER = ServerProperties.getInstance()
			.getProperty("smtp.server.banner", "ESMTP Postfix (Debian/GNU)");
	private final String BLANK = " ";

	private final char MESSAGEID[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	private final String IN = "> ";
	private final String OUT = "< ";

	public Smtp(Socket socket) {
		this.socket = socket;
	}

	@Override
	public void run() {

		String threadid = Thread.currentThread().getId() + " :";

		PrintStream out = null;
		BufferedReader in = null;

		try {

			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH.mm.ss");

			System.out.println(threadid + ":" + dateFormat.format(new Date())
					+ ":" + socket.getRemoteSocketAddress());

			socket.setSoTimeout(20 * 1000);
			in = new BufferedReader(new InputStreamReader(
					socket.getInputStream()));
			out = new PrintStream(socket.getOutputStream());

			String line = null;
			int step = 0;
			int returncode = 0;
			StringBuilder returnstring = new StringBuilder();
			try {
				Thread.sleep((long) (Math.random() * 2000));
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			out.print("220 " + SERVER_NAME + " " + SERVER_BANNER + "\r\n");
			System.out.println(threadid + OUT + "220 " + SERVER_NAME + " "
					+ SERVER_BANNER);

			while ((line = in.readLine()) != null) {
				System.out.println(threadid + IN + line);
				String line_lc = line.toLowerCase();
				String[] tmp = line_lc.split(" ");
				String command = null;
				if (tmp.length > 0) {
					command = tmp[0];
				} else {
					command = line_lc;
				}
				returncode = 0;

				if (step == 12) {
					if (checkbase64(command)) {
						step = 13;
						returnstring = new StringBuilder("334 UGFzc3dvcmQ6");
					} else {
						returnstring = new StringBuilder(
								"535 5.7.8 Error: authentication failed: another step is needed in authentication");
						step = 0;
					}

				} else if (step == 13) {
					if (checkbase64(command)) {
						step = 0;
						returnstring = new StringBuilder("235 2.7.0 Authentication successful.");
					} else {
						returnstring = new StringBuilder(
								"535 5.7.8 Error: authentication failed: another step is needed in authentication");
						step = 0;
					}

				} else if (command.equals("helo")) {
					returncode = helo(line_lc);
					returnstring = helo(returncode);
				} else if (command.equals("ehlo")) {
					returncode = ehlo(line_lc);
					returnstring = ehlo(returncode);
				} else if (command.equals("auth")) {
					returncode = auth(line_lc);
					returnstring = auth(returncode);
					if (returncode == 334) {
						step = 12;
					}
				} else if (command.equals("noop")) {
					returncode = noop(line_lc);
					returnstring = noop(returncode);
				} else if (command.equals("rset")) {
					returncode = rset(line_lc);
					returnstring = rset(returncode);
					step = 0;
				} else if (command.equals("mail")) {
					returncode = mail(line_lc);
					returnstring = mail(returncode);
					if (returncode == 250) {
						step = 2;
					}
				} else if (command.equals("rcpt")) {
					returncode = rcpt(line_lc, step);
					returnstring = rcpt(returncode);
					if (returncode == 250) {
						step = 3;
					}
				} else if (command.equals("data")) {
					if (step < 3) {
						returnstring = new StringBuilder(
								"503 5.5.1 Error: need RCPT command");
					} else {
						out.print("354 End data with <CR><LF>.<CR><LF>\r\n");
						while ((line = in.readLine()) != null) {
							System.out.println(threadid + IN + line);
							if (line.equals(".")) {
								break;
							}
						}
						returnstring = new StringBuilder(
								"250 2.0.0 Ok: queued as " + randomuid());
						step = 0;
					}
				} else if (command.equals("quit")) {
					out.print("221 2.0.0 Bye\r\n");
					return;
				} else {
					if (line_lc.length() == 0) {
						returnstring = new StringBuilder(
								"500 5.5.2 Error: bad syntax");
					} else {
						returnstring = new StringBuilder(
								"502 5.5.2 Error: command not recognized");
					}
				}
				returnstring.append("\r\n");
				out.print(returnstring.toString());
				System.out.println(threadid + OUT + returnstring.toString());
			}
			System.out.println(threadid + "OFF\n");

		} catch (SocketTimeoutException e) {
			out.print("421 4.4.2 " + SERVER_NAME
					+ " Error: timeout exceeded\r\n");
			System.out.println(threadid + "TIMEOUT");
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (out != null) {
				out.close();
			}

			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	private StringBuilder auth(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		if (returncode == 5351) {
			returnstring
					.append("535 5.7.8 Error: authentication failed: authentication failure");
		} else if (returncode == 334) {
			returnstring.append("334 VXNlcm5hbWU6");
		} else {
			returnstring
					.append("535 5.7.8 Error: authentication failed: another step is needed in authentication");
		}
		return returnstring;
	}

	private boolean checkbase64(String string) {
		if (string == null) {
			return false;
		}
		if (string
				.matches("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")) {
			return true;
		}
		return false;
	}

	private int auth(String line) {
		if (line.startsWith("auth plain ")) {
			String[] tmp = line.split(" ");
			if (tmp.length > 2) {
				if (checkbase64(tmp[2])) {
					return 5351;
				}
			}
		} else if (line.equals("auth login")) {
			return 334;
		}
		return 535;
	}

	private String randomuid() {

		// EC17684B48

		StringBuilder tmp = new StringBuilder();
		for (int i = 0; i < 10; i++) {
			tmp.append(MESSAGEID[(int) (Math.random() * MESSAGEID.length)]);
		}
		return tmp.toString();
	}

	private int rcpt(String line, int step) {
		if (step < 2) {
			return 503;
		}

		if (line.startsWith("rcpt to:")) {
			String[] tmp = line.split(":");
			if (tmp.length > 1) {
				return 250;
			}
		}
		return 501;
	}

	private StringBuilder rcpt(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		if (returncode == 250) {
			returnstring.append("250 2.1.5 Ok");
		} else if (returncode == 503) {
			returnstring.append("503 5.5.1 Error: need MAIL command");

		} else {
			returnstring.append("501 5.5.4 Syntax: RCPT TO:<address>");
		}
		return returnstring;
	}

	private int mail(String line) {
		if (line.startsWith("mail from:")) {
			String[] tmp = line.split(":");
			if (tmp.length > 1) {
				return 250;
			}
		}
		return 501;
	}

	private StringBuilder mail(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		if (returncode == 250) {
			returnstring.append("250 2.1.0 Ok");
		} else {
			returnstring.append("501 5.5.4 Syntax: MAIL FROM:<address>");
		}
		return returnstring;
	}

	private int helo(String line) {
		String[] tmp = line.split(" ");
		if (tmp.length > 1) {
			return 250;
		}
		return 501;
	}

	private int ehlo(String line) {
		return helo(line);
	}

	private StringBuilder helo(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		if (returncode == 250) {
			returnstring.append(returncode);
			returnstring.append(BLANK);
			returnstring.append(SERVER_NAME);
		} else {
			returnstring.append("501 Syntax: HELO hostname");
		}
		return returnstring;
	}

	private StringBuilder ehlo(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		if (returncode == 250) {
			returnstring.append("250-");
			returnstring.append(SERVER_NAME);
			returnstring
					.append("\r\n250-PIPELINING\r\n250-SIZE 120000000\r\n250-VRFY\r\n250-ETRN\r\n250-AUTH PLAIN LOGIN\r\n250-AUTH=PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN");

		} else {
			returnstring.append("501 Syntax: EHLO hostname");
		}

		return returnstring;
	}

	private int noop(String line) {
		return 250;
	}

	private StringBuilder noop(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		returnstring.append("250 2.0.0 Ok");
		return returnstring;
	}

	private int rset(String line) {
		String[] tmp = line.split(" ");
		if (tmp.length <= 1) {
			return 250;
		}
		return 501;
	}

	private StringBuilder rset(int returncode) {
		StringBuilder returnstring = new StringBuilder();
		if (returncode == 250) {
			returnstring.append("250 2.0.0 Ok");
		} else {
			returnstring.append("501 5.5.4 Syntax: RSET");
		}
		return returnstring;
	}

}
