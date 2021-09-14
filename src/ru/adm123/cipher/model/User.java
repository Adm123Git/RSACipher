package ru.adm123.cipher.model;

import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * @author Dmitry Ushakov on 14.09.21
 * <p>
 * Класс юзера
 */
public class User {

    @NotNull
    private String name;
    @NotNull
    private final KeyPair keyPair;

    /**
     * В конструкторе сразу делаем пару ключей для этого юзера
     *
     * @param name Имя юзера
     */
    public User(@NotNull String name) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        this.name = name;
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    public void setName(@NotNull String name) {
        this.name = name;
    }

    @NotNull
    public String getName() {
        return name;
    }

    /**
     * Получение публичного ключа. Его будем цеплять к сообщению при отправке.
     *
     * @return Публичный ключ
     */
    @NotNull
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    /**
     * Отправка сообщения. Выводим инфу о том, что отправляем сообщение и его текст в зашифрованном виде
     *
     * @param recipient Получатель
     * @param messageText Текст для отправки
     */
    public void sendMessage(@NotNull User recipient,
                            @NotNull String messageText)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            Message message = new Message(this, recipient, messageText);
            System.out.println("=================================");
            System.out.println(name + " send message to " + recipient.getName());
            System.out.println("---------------------------------");
            System.out.println(message.getEncryptedText());
            System.out.println("---------------------------------");
            System.out.println("=================================");
            message.send();
    }

    /**
     * Получение сообщения. Выводим инфу о получении и текст в читабельном виде.
     *
     * @param message Полученное сообщение
     */
    public void onReceiveMessage(@NotNull Message message)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("=================================");
        System.out.println(name + " receive message from " + message.getSender().getName());
        System.out.println("---------------------------------");
        System.out.println(message.getDecryptedText(keyPair.getPrivate()));
        System.out.println("---------------------------------");
        System.out.println("=================================");
    }

}
