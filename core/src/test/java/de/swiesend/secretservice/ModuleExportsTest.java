package de.swiesend.secretservice;

import org.junit.jupiter.api.Test;

import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * On the module path, a consumer cannot use a type from a package the module does not export, even
 * when an exported class extends it or a public method returns it. {@code javac -Xlint:exports}
 * warns about this, and nothing in the build turns the warning on; this test reads the compiled
 * module descriptor and checks every public or protected member of every exported class.
 */
class ModuleExportsTest {

    @Test
    void exportedClassesUseOnlyExportedTypesOfTheModule() throws Exception {
        Path classes = Path.of(Secret.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        ModuleDescriptor module = ModuleFinder.of(classes).find("de.swiesend.secretservice")
                .orElseThrow(() -> new AssertionError("no module descriptor in " + classes))
                .descriptor();
        Set<String> exported = module.exports().stream()
                .filter(e -> !e.isQualified())
                .map(ModuleDescriptor.Exports::source)
                .collect(Collectors.toSet());

        List<Class<?>> api = new ArrayList<>();
        for (String pkg : exported) {
            try (Stream<Path> files = Files.list(classes.resolve(pkg.replace('.', '/')))) {
                for (Path file : (Iterable<Path>) files::iterator) {
                    String name = file.getFileName().toString();
                    if (!name.endsWith(".class") || name.equals("package-info.class")) continue;
                    Class<?> c = Class.forName(pkg + "." + name.substring(0, name.length() - 6), false,
                            ModuleExportsTest.class.getClassLoader());
                    if (Modifier.isPublic(c.getModifiers()) && isVisible(c)) api.add(c);
                }
            }
        }
        assertFalse(api.isEmpty(), "the precondition: the exported classes were found");

        Set<String> leaks = new TreeSet<>();
        for (Class<?> c : api) {
            check(c.getGenericSuperclass(), c.getName() + " extends", module, exported, leaks);
            for (Type i : c.getGenericInterfaces()) {
                check(i, c.getName() + " implements", module, exported, leaks);
            }
            for (Field f : c.getDeclaredFields()) {
                if (isApi(f)) check(f.getGenericType(), c.getName() + "." + f.getName(), module, exported, leaks);
            }
            for (Method m : c.getDeclaredMethods()) {
                if (!isApi(m) || m.isSynthetic()) continue;
                check(m.getGenericReturnType(), c.getName() + "." + m.getName() + "() returns", module, exported, leaks);
                checkSignature(m, c.getName() + "." + m.getName() + "()", module, exported, leaks);
            }
            for (Constructor<?> k : c.getDeclaredConstructors()) {
                if (isApi(k) && !k.isSynthetic()) checkSignature(k, c.getName() + "()", module, exported, leaks);
            }
        }
        assertEquals(Set.of(), leaks, "exported API that names a type of an unexported package");
    }

    @Test
    void thePublicImplementationsOfExportedInterfacesAreExported() throws Exception {
        // An exported interface of the low-level API is of no use on the module path without its
        // implementation: gnome-keyring's own interface, which unlocks a collection with its
        // password, had its one implementation in an unexported package.
        Path classes = Path.of(Secret.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        ModuleDescriptor module = ModuleFinder.of(classes).find("de.swiesend.secretservice")
                .orElseThrow(() -> new AssertionError("no module descriptor in " + classes))
                .descriptor();
        Set<String> exported = module.exports().stream()
                .filter(e -> !e.isQualified())
                .map(ModuleDescriptor.Exports::source)
                .collect(Collectors.toSet());

        Set<String> hidden = new TreeSet<>();
        for (String pkg : module.packages()) {
            if (exported.contains(pkg)) continue;
            try (Stream<Path> files = Files.list(classes.resolve(pkg.replace('.', '/')))) {
                for (Path file : (Iterable<Path>) files::iterator) {
                    String name = file.getFileName().toString();
                    if (!name.endsWith(".class") || name.equals("package-info.class")) continue;
                    Class<?> c = Class.forName(pkg + "." + name.substring(0, name.length() - 6), false,
                            ModuleExportsTest.class.getClassLoader());
                    if (!Modifier.isPublic(c.getModifiers()) || !isVisible(c)) continue;
                    for (Class<?> i : c.getInterfaces()) {
                        if (exported.contains(i.getPackageName())) hidden.add(c.getName() + " implements " + i.getName());
                    }
                }
            }
        }
        assertEquals(Set.of(), hidden, "an implementation of an exported interface in an unexported package");
    }

    /** Public, and every enclosing class public too. */
    private static boolean isVisible(Class<?> c) {
        for (Class<?> e = c.getEnclosingClass(); e != null; e = e.getEnclosingClass()) {
            if (!Modifier.isPublic(e.getModifiers())) return false;
        }
        return true;
    }

    /** Reachable from another module: public, or protected in a class that can be extended. */
    private static boolean isApi(Member member) {
        int modifiers = member.getModifiers();
        return Modifier.isPublic(modifiers)
                || (Modifier.isProtected(modifiers) && !Modifier.isFinal(member.getDeclaringClass().getModifiers()));
    }

    private static void checkSignature(Executable e, String where, ModuleDescriptor module, Set<String> exported, Set<String> leaks) {
        for (Type p : e.getGenericParameterTypes()) check(p, where + " takes", module, exported, leaks);
        for (Type x : e.getGenericExceptionTypes()) check(x, where + " throws", module, exported, leaks);
    }

    private static void check(Type type, String where, ModuleDescriptor module, Set<String> exported, Set<String> leaks) {
        if (type instanceof ParameterizedType p) {
            check(p.getRawType(), where, module, exported, leaks);
            for (Type a : p.getActualTypeArguments()) check(a, where, module, exported, leaks);
        } else if (type instanceof GenericArrayType a) {
            check(a.getGenericComponentType(), where, module, exported, leaks);
        } else if (type instanceof WildcardType w) {
            for (Type b : w.getUpperBounds()) check(b, where, module, exported, leaks);
            for (Type b : w.getLowerBounds()) check(b, where, module, exported, leaks);
        } else if (type instanceof Class<?> c) {
            while (c.isArray()) c = c.getComponentType();
            String pkg = c.getPackageName();
            if (module.packages().contains(pkg) && !exported.contains(pkg)) {
                leaks.add(where + " " + c.getName());
            }
        }
    }
}
