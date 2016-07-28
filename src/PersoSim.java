import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.xml.bind.DatatypeConverter;

public class PersoSim {
	
	static Card card = null;
	
	private static final byte FEATURE_EXECUTE_PACE = 0x20;

	public static void main(String[] args) throws NoSuchAlgorithmException, CardException {
		
		/*
		 * set path to pc/sc library, this is only necessary under linux if Java will not find pcsc drivers
		 */
		System.setProperty("sun.security.smartcardio.library", "/usr/local/lib/libpcsclite.so");
		
		/*
		 * get all available terminals in a list
		 */
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("Terminals: " + terminals);
        
        /*
         *  choose a terminal by keyword and raise an error 
         *  if no terminal has been found
         */
        int terminalIndex = chooseTerminal(terminals, "REINER SCT");
        if(terminalIndex == -1){
        	System.err.println("Error: There is no Terminal for given keyword!");
        	return;
        }
        
        /*
         * get terminal by terminal index
         */
        CardTerminal terminal = terminals.get(terminalIndex);
        System.out.println("Terminal: " + terminal);
        
        /*
         * establish a connection to the card
         */
        card = terminal.connect("*");
        System.out.println("Connection Protocoll: " + card.getProtocol());
        
        /*
         * get card channel
         */
        CardChannel channel = card.getBasicChannel();
        System.out.println("channel: " + channel);
		        
		
        
        //--------------- get information about the terminal --------------------------       
        
        
        // vendor name
        ResponseAPDU vendor = channel.transmit(new CommandAPDU(DatatypeConverter.parseHexBinary("FF9A010100")));
        printAPDU(vendor, "vendor");
        
        // product name
        ResponseAPDU product = channel.transmit(new CommandAPDU(DatatypeConverter.parseHexBinary("FF9A010300")));
        printAPDU(product, "product");
        
        // firmware version
        ResponseAPDU firmware = channel.transmit(new CommandAPDU(DatatypeConverter.parseHexBinary("FF9A010600")));
        printAPDU(firmware, "firmware");
        
        // driver version
        ResponseAPDU driver = channel.transmit(new CommandAPDU(DatatypeConverter.parseHexBinary("FF9A010700")));
        printAPDU(driver, "driver");
        
        // get provided features
        byte[] features = card.transmitControlCommand(SCARD_CTL_CODE(3400), new byte[] {});
        println(DatatypeConverter.printHexBinary(features));
        printFeatures(features);

        
        
        //--------------- commands to establishing pace --------------------------  
              
        
        // the Structure of command should be: 02 <L_inputData (short)> <Password-ID> <L_CHAT> <CHAT> <L_PIN> <PIN> <L_CERT_DESC> <CERT_DESC>
        byte[] chat = new byte[] {0x7F, 0x4C, 0x0E, 0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x03, 0x53, 0x01, 0x03};
        
        // establish PACE Channel
        byte[] pace = establishPACEChannel(2, chat, null, null);
        println("PACE02: " + DatatypeConverter.printHexBinary(pace));
     
        
        //--------------- commands to select esign app --------------------------  
        
        
        // application id for the esign app on npa
        byte[] aid  = {(byte) 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E};

        
        // select APDU
        CommandAPDU aid_apdu = new CommandAPDU(0x00,0xA4,0x04,0x00, aid, 0xFF);
        ResponseAPDU selectApp = channel.transmit(aid_apdu);
        printAPDU(selectApp, "SelectApp");
        
        
        //--------------- commands to verify esign pin --------------------------  
        
        // CLA has to be 00 instead of 0C, because the terminal needs a 00 CLA byte and will set this byte to 0C before it sends the apdu to the nPA
        CommandAPDU verify = new CommandAPDU(new byte[] {0x00,0x20,0x00,(byte) 0x81,0x06,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF});
        byte[] verifyResponse = verifyPINDirect(verify);
        println("Verify response: " + DatatypeConverter.printHexBinary(verifyResponse));
        
        
        //--------------- commands to execute signature --------------------------
        
        String data = "das ist ein kleines Beispiel fuer fuer daten die signiert werden sollen";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        
        CommandAPDU signatureAPDU = new CommandAPDU(0x00,0x2A,0x9E,0x9A,hash,0xFF);
        ResponseAPDU signature = channel.transmit(signatureAPDU);
        printAPDU(signature, "Signature");
	}

	
	/**
	 * search for an terminal in terminal list which name contains the keyword
	 */
	private static int chooseTerminal(List<CardTerminal> terminals, String keyword){
		for(int i=0; i<terminals.size(); i++){
			if(terminals.get(i).getName().contains(keyword))
				return i;
		}
			
		return -1;
	}

	
	public static byte[] verifyPINDirect(CommandAPDU xcapdu) throws CardException {

	
		byte[] commandData = new byte[] {
				0x00, //this.timeOut, 
				0x00, //this.timeOut2, 
				(byte) 0x02, //this.formatString,
				(byte) 0x06, //this.pinBlockString, 
				0x00, //this.pinLengthFormat,
				0x06, //this.minPINSize,
				0x06, //this.maxPINSize,
				0x03, //this.entryValidationCondition, 
				(byte)0xFF, //this.numberMessage,
				0x09, //this.langId, 
				0x04, //this.langId2, 
				0x00, //this.msgIndex, 
				0x00, //this.teoPrologue,
				0x00, //this.teoPrologue2, 
				0x00, //this.teoPrologue3, 
		};

	
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
	
		byte[] commandBlock = null;
	
		int pcc = getFeatureControlCode(0x06 /*FEATURE_VERIFY_PIN_DIRECT*/);
	
		try {
		
			bos.write(commandData);
			bos.write((byte)xcapdu.getBytes().length);
			bos.write(0x00);
			bos.write(0x00);
			bos.write(0x00);
			bos.write(xcapdu.getBytes());
		
		
	
		} catch (IOException e) {
			throw new CardException("Error creating terminal command: " + e.getMessage());
		}
	
		commandBlock = bos.toByteArray();
		byte[] rsp = card.transmitControlCommand(pcc, commandBlock);
		return rsp;
	}


	private static void printFeatures(byte[] features){
		for(int i=0; i<features.length/6; i++){
			print("Feature: " + translateFeatureNumber(DatatypeConverter.printHexBinary(new byte[] {features[i*6]})));
			print("\t ControlNumber: " + Integer.parseInt(DatatypeConverter.printHexBinary(new byte[] {	features[i*6+2], 
																										features[i*6+3], 
																										features[i*6+4], 
																										features[i*6+5]}),16));
			println();
		}
	}
	
	private static String translateFeatureNumber(String number){
		switch(number){
			case "01": return "FEATURE_VERIFY_PIN_START";
			case "02": return "FEATURE_VERIFY_PIN_FINISH";
			case "03": return "FEATURE_MODIFY_PIN_START";
			case "04": return "FEATURE_MODIFY_PIN_FINISH";
			case "05": return "FEATURE_GET_KEY_PRESSED";
			case "06": return "FEATURE_VERIFY_PIN_DIRECT";
			case "07": return "FEATURE_MODIFY_PIN_DIRECT";
			case "08": return "FEATURE_MCT_READER_DIRECT";
			case "09": return "FEATURE_MCT_UNIVERSAL";
			case "0A": return "FEATURE_IFD_PIN_PROPERTIES";
			case "0B": return "FEATURE_ABORT";
			case "0C": return "FEATURE_SET_SPE_MESSAGE";
			case "0D": return "FEATURE_VERIFY_PIN_DIRECT_APP_ID";
			case "0E": return "FEATURE_MODIFY_PIN_DIRECT_APP_ID";
			case "0F": return "FEATURE_WRITE_DISPLAY";
			case "10": return "FEATURE_GET_KEY";
			case "11": return "FEATURE_IFD_DISPLAY_PROPERTIES";
			case "12": return "FEATURE_GET_TLV_PROPERTIES";
			case "13": return "FEATURE_CCID_ESC_COMMAND";
			case "20": return "FEATURE_EXECUTE_PACE"; 
		}
		return number + ": invalid feature number!";
	}
	
	private static boolean isWindows(){
	  String os_name = System.getProperty("os.name").toLowerCase();
	  if (os_name.indexOf("windows") > -1) return true;
	  return false;
	}
	
	private static int SCARD_CTL_CODE(int code){
	  int ioctl;
	  if (isWindows()){
	    ioctl = (0x31 << 16 | (code) << 2);
	  } 
	  else {
	    ioctl = 0x42000000 + (code);
	  }
	  return ioctl;
	}
	
	private static void printAPDU(ResponseAPDU r, String name){
		print("\n");
		print("APDU: " + name);
		
		print("\t");
		print(r.toString());
		
		print("\t");
		print("response data: \t");
		for(byte b : r.getData()){
			print(" " + DatatypeConverter.printHexBinary(new byte[] {b}));
	    }
	}
	
	private static void print(String s){
		System.out.print(s);
	}
	
	private static void println(String s){
		System.out.println(s);
	}
	
	private static void println(){
		System.out.println();
	}
	
	public static byte[] joinByteArrays(List<byte[]> arrays){
		
		ArrayList<Byte> bytesAsList = new ArrayList<Byte>();
		
		for(byte[] a : arrays){
			for(int i=0; i<a.length; i++){
				bytesAsList.add(a[i]);
			}
		}
		
		byte[] bytes =  new byte[bytesAsList.size()];
		for(int i=0; i<bytesAsList.size(); i++){
			bytes[i] = bytesAsList.get(i);
		}
		
		return bytes;
	};
	
	public static byte[] establishPACEChannel(int pinid, byte[] chat, byte[] pin, byte[] certdesc) throws CardException {
		//SCardControl
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(0x02); //Index of the PACE function: EstablishPACEChannel
		bos.write(0x00); //Length template
		bos.write(0x00); //Length template
	
		//EstablishPACEChannelInputData
		bos.write(pinid); 
		if(chat != null) {
			bos.write(chat.length);
			bos.write(chat, 0, chat.length);
		} else {
			bos.write(0);
		}
		if(pin != null) {
			bos.write(pin.length);
			bos.write(pin, 0, pin.length);
		} else {
			bos.write(0);
		}
		if(certdesc != null) {
			bos.write((byte) (certdesc.length & 0xFF));
			bos.write((byte) (certdesc.length >> 8));
			bos.write(certdesc, 0, certdesc.length);
		} else {
			bos.write(0);
			bos.write(0);
		}
	
		int inputLength = bos.size() - 3;
	
		byte[] inputData = bos.toByteArray();
		//Writing the length of the EstablishPACEChannelInputData into the template
		inputData[1] = (byte) (inputLength & 0xFF);
		inputData[2] = (byte) (inputLength >> 8);
	
		int PACEControlCode = getFeatureControlCode(FEATURE_EXECUTE_PACE);
		byte[] rpc = card.transmitControlCommand(PACEControlCode, inputData);
	
		long result =  extractLongFromByteArray(rpc, 0, 4);
		System.out.println("PACE result: " + Long.toHexString(result));
	
		return rpc;
	}
	
	public static long getReadersPACECapabilities() throws CardException {
		int PACEControlCode = getFeatureControlCode(FEATURE_EXECUTE_PACE);
	
		//SCardControl
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(0x01); //Index of the PACE function
		bos.write(0x00); //Two byte length field
		bos.write(0x00);
		byte[] commandBlock = bos.toByteArray();
	
		byte[] rpc = card.transmitControlCommand(PACEControlCode, commandBlock);
		long result = extractLongFromByteArray(rpc, 0, 4);
		if(result == 0) {
			long outputData = extractLongFromByteArray(rpc, 6, 1);
			return outputData;
		}
		else{
			return -1;
		}	
	}
	
	public static long extractLongFromByteArray(byte[] buffer, int offset, int length) {
		if((offset + length) > buffer.length) {
			throw new IndexOutOfBoundsException("Length exceeds buffer size");
		}
		if(length > 8) {
			throw new IllegalArgumentException("Cannot decode more than 8 byte");
		}
		
		long c = 0;
		while (length-- > 0) {
			c <<= 8;
			c |= buffer[offset + length] & 0xFF;
		}
		return c;
	}
	
	public static int getFeatureControlCode(int feature) {
		byte[] features;
	
		int ioctl = (0x31 << 16 | (3400) << 2);
	
		byte[] empty = {};
	
		try {
			features = card.transmitControlCommand(ioctl, empty);
		}
		catch(CardException e) {
			return -1;
		}
	
		int i = 0;
	
		while(i < features.length) {
			if (features[i] == feature) {
				int c = 0;
				i += 2;				
				for (int l = 0; (i < features.length) && (l < 4); i++, l++) {
					c <<= 8;
					c |= features[i] & 0xFF;
				}
	
				return c;
	
			} else {
				i += 6; // skip six bytes
			}
		}
	
		return -1;
	}	

}


