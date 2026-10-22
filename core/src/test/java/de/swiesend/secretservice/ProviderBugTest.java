package de.swiesend.secretservice;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The catalogue of {@link ProviderBug}: what a test may rely on in each entry. */
class ProviderBugTest {

    @Test
    void aReportedBugLinksItsReport() {
        assertEquals(List.of(), bugs(bug -> bug.status == ProviderBug.Status.REPORTED && !isLink(bug.report)));
    }

    @Test
    void anUnreportedBugLinksNoReport() {
        assertEquals(List.of(), bugs(bug -> bug.status == ProviderBug.Status.UNREPORTED && bug.report != null));
    }

    @Test
    void eachBugNamesItsProviderAndVersions() {
        assertEquals(List.of(), bugs(bug -> !bug.name().startsWith(bug.provider.name() + "_")));
        assertEquals(List.of(), bugs(bug -> bug.versions == null || bug.versions.isBlank()));
    }

    @Test
    void theFakeRefusesToReproduceABugItDoesNotReproduce() {
        FakeSecretService fake = new FakeSecretService(null, false);
        for (ProviderBug bug : ProviderBug.values()) {
            if (bug.fake == ProviderBug.Fake.NOT_REPRODUCED) {
                assertThrows(UnsupportedOperationException.class, () -> fake.reproduce(bug), bug.name());
            } else {
                assertDoesNotThrow(() -> fake.reproduce(bug), bug.name());
            }
        }
    }

    private static boolean isLink(String report) {
        return report != null && report.startsWith("https://");
    }

    private static List<ProviderBug> bugs(java.util.function.Predicate<ProviderBug> failing) {
        return Arrays.stream(ProviderBug.values()).filter(failing).toList();
    }
}
