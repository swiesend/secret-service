package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.ConsentPolicy.Operation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static de.swiesend.secretservice.functional.ConsentPolicy.Requirement.CALLBACK;
import static de.swiesend.secretservice.functional.ConsentPolicy.Requirement.NONE;
import static de.swiesend.secretservice.functional.ConsentPolicy.Requirement.PROVIDER_PROMPT;
import static de.swiesend.secretservice.functional.ConsentPolicy.WhenUnavailable.PROCEED;
import static de.swiesend.secretservice.functional.ConsentPolicy.WhenUnavailable.REFUSE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The value semantics of {@link ConsentPolicy}. What the gate does with a policy is in ConsentGateTest. */
class ConsentPolicyTest {

    @Test
    void noneRequiresNothingForAnyOperation() {
        for (Operation operation : Operation.values()) {
            assertEquals(NONE, ConsentPolicy.none().requirement(operation), operation.name());
        }
        assertEquals(Duration.ZERO, ConsentPolicy.none().remembered(), "nothing is remembered");
    }

    @Test
    void legacyIsTheBehaviourOf3x() {
        ConsentPolicy legacy = ConsentPolicy.legacy();
        assertEquals(PROVIDER_PROMPT, legacy.requirement(Operation.READ_ALL));
        assertEquals(REFUSE, legacy.whenUnavailable(Operation.READ_ALL), "3.x refused a bulk read");
        assertEquals(PROVIDER_PROMPT, legacy.requirement(Operation.DELETE_ONE));
        assertEquals(PROCEED, legacy.whenUnavailable(Operation.DELETE_ONE), "3.x deleted anyway");
        assertEquals(PROVIDER_PROMPT, legacy.requirement(Operation.DELETE_MANY));
        assertEquals(PROCEED, legacy.whenUnavailable(Operation.DELETE_MANY));
        assertEquals(ConsentPolicy.UNTIL_CLOSED, legacy.remembered(), "3.x asked once per collection object");
    }

    @Test
    void requireReturnsANewPolicyAndLeavesTheOriginalAlone() {
        ConsentPolicy none = ConsentPolicy.none();
        ConsentPolicy strict = none.require(Operation.DELETE_ONE, PROVIDER_PROMPT);

        assertEquals(PROVIDER_PROMPT, strict.requirement(Operation.DELETE_ONE));
        assertEquals(REFUSE, strict.whenUnavailable(Operation.DELETE_ONE), "refusing is the default");
        assertEquals(NONE, strict.requirement(Operation.READ_ALL), "only the named operation changes");
        assertEquals(NONE, none.requirement(Operation.DELETE_ONE), "the original policy is unchanged");
    }

    @Test
    void rememberRejectsANegativeDuration() {
        assertThrows(IllegalArgumentException.class, () -> ConsentPolicy.none().remember(Duration.ofSeconds(-1)));
        assertEquals(Duration.ofMinutes(5), ConsentPolicy.none().remember(Duration.ofMinutes(5)).remembered());
    }

    @Test
    void theHandlerStaysWhenThePolicyChangesOtherwise() {
        ConsentPolicy.Handler handler = request -> true;
        ConsentPolicy policy = ConsentPolicy.none()
                .handler(handler)
                .require(Operation.READ_ALL, CALLBACK)
                .remember(Duration.ofMinutes(1));

        assertEquals(Optional.of(handler), policy.handler());
        assertEquals(Optional.empty(), ConsentPolicy.none().handler(), "none() has no handler");
    }

    @Test
    void aRequestKeepsItsOwnCopyOfTheItemPaths() {
        List<String> paths = new ArrayList<>(List.of("/a"));
        ConsentPolicy.Request request = new ConsentPolicy.Request(Operation.DELETE_MANY, "/c", paths);
        paths.add("/b");

        assertEquals(List.of("/a"), request.itemPaths());
    }

    @Test
    void policiesThatBehaveAlikeAreEqual() {
        assertEquals(ConsentPolicy.legacy(), ConsentPolicy.legacy());
        assertEquals(ConsentPolicy.legacy().hashCode(), ConsentPolicy.legacy().hashCode());
        assertNotEquals(ConsentPolicy.none(), ConsentPolicy.legacy());
        assertEquals(ConsentPolicy.none(), ConsentPolicy.none().require(Operation.READ_ALL, NONE),
                "naming an operation as NONE is the same as not naming it");
    }
}
