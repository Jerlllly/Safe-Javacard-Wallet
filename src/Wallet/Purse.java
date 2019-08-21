package Wallet;

import javacard.framework.*;

public class Purse extends Applet {
	CyclicFile record;
	ExternalAuthentication ea;
	InternalAuthentication ia;
	OwnerPIN pin;
	short balance;
	 final static byte VERIFY = (byte) 0x20;
	final static byte CREDIT = (byte) 0x30;
	final static byte DEBIT = (byte) 0x40;
	final static byte GET_BALANCE = (byte) 0x50;
	final static byte GET_HISTORY = (byte) 0x60;
	final static short EA_RETURN_RANDOM=(byte)0x84;
	final static short EA_DO=(byte)0x82;
	final static short IA_DO=(byte)0x88;
	final static short IA_SURE=(byte)0x89;
	final static short MAX_BALANCE = 0x7FFF;
    final static byte MAX_TRANSACTION_AMOUNT = 127;
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    final static short SIZE = 0x2;
    final static byte PIN_TRY_LIMIT =(byte)0x03;
    final static byte MAX_PIN_SIZE =(byte)0x08;
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	final static short SW_IAEA_VERIFICATION_REQUIRED = 0x6302;
	protected Purse()//Wallet���캯��
	{	
		byte pinInitValue[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		pin.update(pinInitValue, (short) 0, (byte) 6);
		record=new CyclicFile((short)2,(short)5);//��record����ռ�
		ea=new ExternalAuthentication();
		ia=new InternalAuthentication();
		register();//ע��
	}
	public boolean select() 
	{

		    // The applet declines to be selected
		    // if the pin is blocked.
		if ( pin.getTriesRemaining() == 0 )
			return false;
		else
		    return true;

	}
	 public void deselect() 
	 {

		    // reset the pin value
		 pin.reset();
	 }

	public static void install (byte[] bArray,short bOffset,byte bLength)
	{
		new Purse();//install����ʵ����wallet
	}
	
	public void process(APDU apdu) throws ISOException 
	{
		// TODO Auto-generated method stub
		byte[] buffer=apdu.getBuffer();//��ȡ����APDU���������
		if((buffer[ISO7816.OFFSET_INS]==(byte)0xA4)&&(buffer[ISO7816.OFFSET_CLA]==(byte)0x00))//���CLA INSΪ00A4����ѡ�����Applet
		{
			return;
		}
		if(buffer[ISO7816.OFFSET_CLA]!=(byte)0x80)//CLAΪ80�������Applet�Ĺ��ܲ��֣������׳��쳣
		{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		switch(buffer[ISO7816.OFFSET_INS])//���ܷ�֧
		{
			case GET_BALANCE:   getBalance(apdu);
			return;
			case DEBIT:         debit(apdu);
			return;
			case CREDIT:        credit(apdu);
			return;
			case GET_HISTORY:   getHistory(apdu);
			return;
			case VERIFY:        verify(apdu);
            return;
			case EA_RETURN_RANDOM:
			{
				ea.getRandom();
				//�������ɵ�8�ֽ������
				Util.arrayCopyNonAtomic(ea.Random,(short)0,buffer,(short)0,(short)8);
				apdu.setOutgoingAndSend((short)0, (short)8);

			};
			return;
			case EA_DO:
			{
				apdu.setIncomingAndReceive();
				ea.doAuthentication(buffer);
			};
			return;
			case IA_DO:
			{
				apdu.setIncomingAndReceive();
				ia.doAuthentication(buffer);
				apdu.setOutgoingAndSend((short)0, (short)8);
			};
			return;
			case IA_SURE:
			{
				apdu.setIncomingAndReceive();
				ia.ChangeFlag();
			};
			return;
			default:       ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
									
		}
	}
	private void debit(APDU apdu)
	{
		if ( ! pin.isValidated() )
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		if ( ia.getFlag()!=0x1||ea.getFlag()!=0x1 )
			ISOException.throwIt(SW_IAEA_VERIFICATION_REQUIRED);
		JCSystem.beginTransaction();
		byte[] buffer = apdu.getBuffer();
		byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC]);
	    byte byteRead = (byte)(apdu.setIncomingAndReceive());
	    if ( ( numBytes != 1 ) || (byteRead != 1) )
	    	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		    // ȡ�������ѵ�ֵ
	    byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
		    // �ж����ѽ��׶���Ƿ�����Ҫ��
	    if ( ( debitAmount > MAX_TRANSACTION_AMOUNT)  ||  ( debitAmount < 0 ) )
	    	ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		    // �ж�Ǯ������Ƿ�������ѵ������Ǯ���Ƿ�͸֧
	    if ( (short)( balance - debitAmount ) < (short)0 )
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);
   		    // ����������ȫ�����㣬������Ǯ�����
	    {
	    	balance = (short) (balance - debitAmount);
	    	byte []temp=new byte[2];
	    	temp[0]=0;
	    	temp[1]=debitAmount;
	    	record.AppendRecord(temp, SIZE);
	    }
	    JCSystem.commitTransaction();
	}
	private void credit(APDU apdu)
	{
		if ( ! pin.isValidated() )
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		if ( ia.getFlag()!=0x1||ea.getFlag()!=0x1 )
			ISOException.throwIt(SW_IAEA_VERIFICATION_REQUIRED);
		JCSystem.beginTransaction();
		byte[] buffer = apdu.getBuffer();
	    // ȡ����LC������֮�洢��numBytes��
		byte numBytes = buffer[ISO7816.OFFSET_LC];
	    // ����APDU�������ݣ�����֮�洢��APDUͨ�Ż�������
	    // ISO7816.OFFSET_CDATA��������5�ֽڵ�APDU����ͷ
	    byte byteRead = (byte)(apdu.setIncomingAndReceive());
	    // �ж�LC�Ƿ�Ϊ1�������׳��쳣����Ӧ��ֻ֧��һ���ֽڳ��ȵĴ�Ǯ����
	    if ( ( numBytes != 1 ) || (byteRead != 1) )
	     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    // ȡ�������ֵ
	    byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
	    // �жϽ��׶��Ƿ�����Ҫ��
	    if ( ( creditAmount > MAX_TRANSACTION_AMOUNT) || ( creditAmount < 0 ) )
	        ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
	    // �ж������д�Ǯ���ף�����Ƿ񳬳��������ֵ
	    if ( (short)( balance + creditAmount)  > MAX_BALANCE )
	       ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
	    // ����������ȫ�����㣬�����Ǯ�����
	    balance = (short)(balance + creditAmount);
	    byte []temp=new byte[2];
    	temp[0]=1;
    	temp[1]=creditAmount;
    	record.AppendRecord(temp, SIZE);
	    JCSystem.commitTransaction();
	}
	private void getBalance(APDU apdu)
	{
		if ( ia.getFlag()!=0x1||ea.getFlag()!=0x1 )
			ISOException.throwIt(SW_IAEA_VERIFICATION_REQUIRED);
		 byte[] buffer = apdu.getBuffer();
		 	// ����ͨ�Ŵ��䷽��Ϊ��Ƭ���նˣ�ͬʱҲ��ʾ��Ƭ���н�����
		    // ׼������������Ӧ���նˣ�����leΪAPDU�����е�LE��
		    // ��ʾ�ն�Ҫ��Ƭ���ص���Ӧ���ݵĳ���
		 short le = apdu.setOutgoing();
		 if ( le < 2 )
			 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		    // ���ÿ�Ƭ�������ݵ�ʵ�ʳ���
		 apdu.setOutgoingLength((byte)2);
		    // ����������ݵ�APDU�������У�׼�����͸��ն�
		 buffer[0] = (byte)(balance >> 8);
		 buffer[1] = (byte)(balance & 0xFF);
		    // ����ͨ�ź��������������
	    apdu.sendBytes((short)0, (short)2);
	}
	private void getHistory(APDU apdu)
	{
		if ( ia.getFlag()!=0x1||ea.getFlag()!=0x1 )
			ISOException.throwIt(SW_IAEA_VERIFICATION_REQUIRED);
		byte[] buffer=apdu.getBuffer();//APDU��ȡ��������
		byte[] data;//����
		short num = 0;
		if(buffer[ISO7816.OFFSET_P1]==0x01)//P1Ϊ01����ѯ��ѡ��¼
		{
			num = Util.makeShort((byte)0x00,buffer[ISO7816.OFFSET_P2]);//��ѯ���ΪP2
		}
		else//�׳��쳣
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if(num>record.maxrecord)//��Ŵ��ڼ�¼�ļ��ɴ����ֵ���׳��쳣
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if(record.currentrecord == -1)//�׳��쳣
		{
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		data=record.ReadRecord(num);//��ȡ��Ӧ����
		apdu.setOutgoing();
		apdu.setOutgoingLength(record.recordsize);
		apdu.sendBytesLong(data,(short)0,record.recordsize);

	}
	  private void verify(APDU apdu) 
	  {

		  byte[] buffer = apdu.getBuffer();
		  byte byteRead = (byte)(apdu.setIncomingAndReceive());
		  		  if ( pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false )
			  ISOException.throwIt(SW_VERIFICATION_FAILED);

		} // end of validate method

}
