package chat.gryt.keycloak.pairing;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class MaskEmailTest {

    @Test
    void keepsOnlyFirstLettersAndTheEnding() {
        assertEquals("s•••@g•••.com", PairingResource.maskEmail("someone@gmail.com"));
        assertEquals("s•••@e•••.uk", PairingResource.maskEmail("s@example.co.uk"));
    }

    @Test
    void neverReturnsAWholeUsername() {
        assertEquals("s•••", PairingResource.maskEmail("someone"));
        assertEquals("", PairingResource.maskEmail(""));
    }
}
