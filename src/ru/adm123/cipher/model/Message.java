package ru.adm123.cipher.model;

import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * @author Dmitry Ushakov on 14.09.21
 * <p>
 * Класс сообщения чата
 */
public class Message {

    @NotNull
    private final User sender;
    @NotNull
    private final User recipient;
    private final String encryptedText;

    /**
     * @param sender    Отправитель
     * @param recipient Получатель
     * @param text      Текст сообщения. Его сразу шифруем с помощью шифра для шифрования
     */
    public Message(@NotNull User sender,
                   @NotNull User recipient,
                   @NotNull String text)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.sender = sender;
        this.recipient = recipient;
        this.encryptedText = Base64.getEncoder().encodeToString(getEncryptCipher().doFinal(text.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Отправка сообщения. По факту просто вызываем метод получателя, где он реагирует на получение сообщения
     */
    public void send()
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        recipient.onReceiveMessage(this);
    }

    /**
     * Получение отправителя сообщения. Например, для отправки ответа
     * @return Отправитель
     */
    @NotNull
    public User getSender() {
        return sender;
    }

    /**
     * Вывод зашифрованного текста сообщения
     *
     * @return Зашифрованный текст сообщения
     */
    public String getEncryptedText() {
        return encryptedText;
    }

    /**
     * Получение текста сообщения в читабельном виде (используем на стороне получателя, поэтому нужен его приватный ключ)
     *
     * @param privateKey Приватный ключ для расшифровки сообщения
     * @return Расшифрованный текст сообщения
     */
    public String getDecryptedText(@NotNull PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return new String(getDecryptCipher(privateKey).doFinal(Base64.getDecoder().decode(encryptedText)), StandardCharsets.UTF_8);
    }

    /**
     * Получение шифра для шифрования текста сообщения с помощью публичного ключа
     *
     * @return Шифр
     */
    @NotNull
    private Cipher getEncryptCipher()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, recipient.getPublicKey());
        return cipher;
    }

    /**
     * Получение шифра для расшифровки сообщения
     *
     * @param privateKey Приватный ключ для расшифровки сообщения
     * @return Шифр
     */
    @NotNull
    private Cipher getDecryptCipher(@NotNull PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher;
    }

}
