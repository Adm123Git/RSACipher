package ru.adm123.cipher;

import ru.adm123.cipher.model.User;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Dmitry Ushakov on 14.09.21
 */
public class Main {

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        User user1 = new User("USER_1");
        User user2 = new User("USER_2");
        user1.sendMessage(user2, "message text");
    }

}
