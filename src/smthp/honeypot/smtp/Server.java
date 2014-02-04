package smthp.honeypot.smtp;


import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import smthp.honeypot.ServerProperties;


public class Server {

	public static void main(String[] args) {
		ServerProperties properties = ServerProperties.getInstance();
		int poolsize = Integer.parseInt(properties.getProperty(
				"smtp.threadpool.size", "100"));
		int port = Integer.parseInt(properties.getProperty("smtp.server.port",
				"4444"));
		int backlog = Integer.parseInt(properties.getProperty("smtp.server.backlog",
				"0"));
		
		InetAddress inetaddr = null;
		if (properties.getProperty("smtp.server.bindaddress") != null) {
			try {
				inetaddr = InetAddress.getByName(properties.getProperty("smtp.server.bindaddress"));
			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
		}

		final ExecutorService pool = Executors.newFixedThreadPool(poolsize);
		try {

			ServerSocket listener = new ServerSocket(port, backlog, inetaddr);
			while (true) {
				pool.execute(new Smtp(listener.accept()));
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pool.shutdown();
			System.out.println("Shutdown");
		}
	}
}
