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
	protected Purse()//Wallet构造函数
	{	
		byte pinInitValue[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		pin.update(pinInitValue, (short) 0, (byte) 6);
		record=new CyclicFile((short)2,(short)5);//给record分配空间
		ea=new ExternalAuthentication();
		ia=new InternalAuthentication();
		register();//注册
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
		new Purse();//install过程实例化wallet
	}
	
	public void process(APDU apdu) throws ISOException 
	{
		// TODO Auto-generated method stub
		byte[] buffer=apdu.getBuffer();//读取传入APDU命令到缓冲区
		if((buffer[ISO7816.OFFSET_INS]==(byte)0xA4)&&(buffer[ISO7816.OFFSET_CLA]==(byte)0x00))//如果CLA INS为00A4代表选择这个Applet
		{
			return;
		}
		if(buffer[ISO7816.OFFSET_CLA]!=(byte)0x80)//CLA为80进入这个Applet的功能部分，否则抛出异常
		{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		switch(buffer[ISO7816.OFFSET_INS])//功能分支
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
				//返回生成的8字节随机数
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
		    // 取即将消费的值
	    byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
		    // 判断消费交易额度是否满足要求
	    if ( ( debitAmount > MAX_TRANSACTION_AMOUNT)  ||  ( debitAmount < 0 ) )
	    	ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		    // 判断钱包余额是否大于消费的数额，即钱包是否透支
	    if ( (short)( balance - debitAmount ) < (short)0 )
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);
   		    // 若以上条件全部满足，最后更改钱包余额
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
	    // 取命令LC，并将之存储在numBytes中
		byte numBytes = buffer[ISO7816.OFFSET_LC];
	    // 接收APDU命令数据，并将之存储在APDU通信缓冲区的
	    // ISO7816.OFFSET_CDATA处，接着5字节的APDU命令头
	    byte byteRead = (byte)(apdu.setIncomingAndReceive());
	    // 判断LC是否为1，否则抛出异常。本应用只支持一个字节长度的存钱交易
	    if ( ( numBytes != 1 ) || (byteRead != 1) )
	     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    // 取将存入的值
	    byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
	    // 判断交易额是否满足要求
	    if ( ( creditAmount > MAX_TRANSACTION_AMOUNT) || ( creditAmount < 0 ) )
	        ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
	    // 判断若进行存钱交易，余额是否超出允许最大值
	    if ( (short)( balance + creditAmount)  > MAX_BALANCE )
	       ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
	    // 若以上条件全部满足，则更新钱包余额
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
		 	// 设置通信传输方向为卡片到终端，同时也表示卡片运行结束，
		    // 准备发送命令响应给终端，其中le为APDU命令中的LE，
		    // 表示终端要求卡片返回的响应数据的长度
		 short le = apdu.setOutgoing();
		 if ( le < 2 )
			 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		    // 设置卡片发送数据的实际长度
		 apdu.setOutgoingLength((byte)2);
		    // 复制余额数据到APDU缓冲区中，准备发送给终端
		 buffer[0] = (byte)(balance >> 8);
		 buffer[1] = (byte)(balance & 0xFF);
		    // 调用通信函数发送余额数据
	    apdu.sendBytes((short)0, (short)2);
	}
	private void getHistory(APDU apdu)
	{
		if ( ia.getFlag()!=0x1||ea.getFlag()!=0x1 )
			ISOException.throwIt(SW_IAEA_VERIFICATION_REQUIRED);
		byte[] buffer=apdu.getBuffer();//APDU读取到缓冲区
		byte[] data;//数据
		short num = 0;
		if(buffer[ISO7816.OFFSET_P1]==0x01)//P1为01，查询可选记录
		{
			num = Util.makeShort((byte)0x00,buffer[ISO7816.OFFSET_P2]);//查询序号为P2
		}
		else//抛出异常
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if(num>record.maxrecord)//序号大于记录文件可存最大值，抛出异常
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if(record.currentrecord == -1)//抛出异常
		{
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		data=record.ReadRecord(num);//读取对应数据
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
