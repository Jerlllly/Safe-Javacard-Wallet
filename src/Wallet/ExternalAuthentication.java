package Wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class ExternalAuthentication {

	byte [] Random;
	private DESKey deskey;
	Cipher  CipherObj;
	short flag=0x00;
	  //单重DES密钥
	private byte[] keyData = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	  

public void doAuthentication(byte [] buffer) {
			
	
		//生成密钥对象
	      deskey=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
							
	      //设置ＤＥＳ密钥					
	      deskey.setKey(keyData, (short)0);
	      
	      //生成加密对象
	      CipherObj   = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	      
	      //初始化密钥及加密模式
	      CipherObj.init(deskey, Cipher.MODE_ENCRYPT);
	      
	       //加密
	       CipherObj.doFinal(Random, (short)0, (short)8, buffer, (short)13); 
	       
	       //比较数据域与加密结果
	       if ( Util.arrayCompare(buffer,(short)5, buffer, (short)13,(short)8)
	    		   != 0 )
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	       else
	    	   flag=0x01;
	}

	public void getRandom() {
		
		//创建存放随机数的数组
		if ( Random == null )
			Random = JCSystem.makeTransientByteArray((short)16,JCSystem.CLEAR_ON_DESELECT);
		
		//获得生成随机数的对象实例
		RandomData ICC = RandomData.getInstance((byte)RandomData.ALG_PSEUDO_RANDOM );
		
		//设置随机数的种子并产生8字节的随机数
		ICC.setSeed(Random,(short)0,(short)8 );
        ICC.generateData(Random,(short)0,(short)8);

	}
	public short getFlag()
	{
		short result=flag;
		return result;
	}
}
