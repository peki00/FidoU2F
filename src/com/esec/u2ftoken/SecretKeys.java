package com.esec.u2ftoken;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/** 
 * @author Yang Zhou 
 * @version 幹秀扮寂?2015-12-10 和怜06:51:23 
 * 嚥畜埒?購議荷恬才方象撃廾窃
 */
public class SecretKeys {
	
	public static final byte MODE_ENCRYPT = 0x01; // 紗畜庁塀
	public static final byte MODE_DECRYPT = 0x02; // 盾畜庁塀
	
	public static final byte KEY_TYPE_AES = 0x01; // 云幣箭隠贋議頁AES畜埒
	public static final byte KEY_TYPE_DES = 0x02; // 云幣箭隠贋議頁DES畜埒
	
//	private byte mKeyType = 0x00;
	
	/**
	 * 畜埒議糞悶?DES
	 */
//	private DESKey mDESKeyInstance = null;
	
	/**
	 * 畜埒議糞悶?AES
	 */
	private AESKey mAESKeyInstance = null;
	
	/**
	 * 兜兵晒key wrap麻隈議畜埒
	 * 寡喘AES-256?伏撹議AES畜埒嗤256了
	 * 寡喘DES3-2KEY?伏撹議DES畜埒嗤128了
	 */
	public SecretKeys(byte keyType) {
//		mKeyType = keyType;
//		if (mKeyType == KEY_TYPE_DES) {
////			mDESKeyInstance = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
//			mDESKeyInstance = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
//			byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
//			Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
//			mDESKeyInstance.setKey(keyData, (short) 0);
//		} else if (mKeyType == KEY_TYPE_AES) {
			try {
				// TODO 宸戦嗤泣諒籾?短嗤宸倖麻隈?
				mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			} catch(CryptoException e) {
//				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
//			mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			// TODO 頁音頁宸戦嗤危?????AES-256哘乎頁32忖准??
			byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
			mAESKeyInstance.setKey(keyData, (short) 0);
//		} else {
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//		}
		
	}
	
	/**
	 * key wrap麻隈?宸戦寡喘 AES-256 議 ALG_AES_BLOCK_128_CBC_NOPAD
	 * @param data 俶勣 wrap 議方象
	 * @param inOffset
	 * @param inLength
	 * @param outBuff
	 * @param outOffset
	 * @param mode 紗畜賜盾畜。 Cipher.MODE_ENCRYPT 賜 Cipher.MODE_DECRYPT
	 */
	public void keyWrap(byte[] data, short inOffset, short inLength, byte[] buffer, short outOffset, byte mode) {
		Cipher cipher = null;
//		if (mKeyType == KEY_TYPE_DES) {
////			cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
//			cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
//			cipher.init(mDESKeyInstance, mode); // 兜兵?楚(iv)頁0
//		} else if (mKeyType == KEY_TYPE_AES) {
//			cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			try {
				// Cipher.getInstance壓宸戦狛音阻?壓U2FToken戦嬬狛???
				cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
			} catch (CryptoException e) {
				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
			cipher.init(mAESKeyInstance, mode); // 兜兵?楚(iv)頁0
//		}
		
		// 紗畜賜盾畜?doFinal朔?cipher斤?繍瓜嶷崔
		try {
			cipher.doFinal(data, inOffset, inLength, buffer, outOffset);
		} catch(Exception e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}
}
