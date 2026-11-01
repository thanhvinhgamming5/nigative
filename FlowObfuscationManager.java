package obfuscator.flow;

import archive.InputFileLocation;
import archive.SourceArchive;
import changelog.ChangeLogMapping;
import changelog.ChangeLogMemberEntry;
import changelog.LabeledTuple;
import classfile.AbstractFieldInfo;
import classfile.AbstractMethodInfo;
import classfile.ClassFileBase;
import classfile.FieldInfo;
import classfile.FieldNameTypeSignature;
import classfile.FieldSignature;
import classfile.MethodInfo;
import classfile.MethodSignature;
import classfile.ProgramClass;
import classfile.constpool.ConstantPool;
import classfile.constpool.ResolvedClassConstant;
import classfile.constpool.ResolvedFieldRef;
import classfile.constpool.ResolvedMethodRefConstant;
import classfile.hierarchy.ClassHierarchy;
import classfile.hierarchy.ClassHierarchyNode;
import classfile.hierarchy.ClassHierarchyQuery;
import classfile.hierarchy.ClassMemberLookup;
import classfile.hierarchy.ClassResolver;
import classfile.hierarchy.ClasspathClassFile;
import classfile.hierarchy.InheritedMemberAnalyzer;
import classfile.hierarchy.LibraryFieldInfo;
import classfile.hierarchy.LibraryMethod;
import classfile.insn.BranchInstruction;
import classfile.insn.ConstantRefInstruction;
import classfile.insn.ExceptionHandlerSpec;
import classfile.insn.Instruction;
import classfile.insn.LabelInstruction;
import classfile.insn.LocalVariableList;
import classfile.insn.MethodBytecode;
import classfile.insn.NewArrayInstruction;
import classfile.insn.SimpleInstruction;
import classfile.insn.TypeInstruction;
import config.GroupingsSpec;
import config.HiddenOptionFlags;
import engine.ClassInitOrderHandler;
import engine.ProcessingStatistics;
import exceptions.Exception;
import exceptions.ProcessingException;
import license.EncodedClassNameSource;
import obfuscator.exclude.AbstractExclusionSpec;
import obfuscator.exclude.NameExclusionSet;
import obfuscator.rename.IndexedNameGenerator;
import script.ScriptEnvironment;
import util.Assert;
import util.CountingBag;
import util.EnumerableMap;
import util.IdentityValueHolder;
import util.ListMultimap;
import util.MutableInt;
import util.NamedSet;
import util.ObjectPair;
import util.ObservableHolder;
import util.ReadOnlyMultiMap;
import util.SetMultiMap;
import util.SyncIndexedSet;
import util.Triple;
import util.TwoKeyMap;
import util.Utils;
import util.WeightedObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;

@SuppressWarnings({"rawtypes", "unchecked"})
public class FlowObfuscationManager extends EncodedClassNameSource {

    // ---- JVM opcodes used when emitting bytecode ----
    private static final int OP_ICONST_0 = 3;
    private static final int OP_ICONST_1 = 4;
    private static final int OP_DUP = 89;
    private static final int OP_IFNE = 154;
    private static final int OP_IRETURN = 172;
    private static final int OP_ARETURN = 176;
    private static final int OP_RETURN = 177;
    private static final int OP_GETSTATIC = 178;
    private static final int OP_PUTSTATIC = 179;
    private static final int OP_INVOKESPECIAL = 183;
    private static final int OP_INVOKESTATIC = 184;
    private static final int OP_ANEWARRAY = 189;

    private static final int LOCALS_FLAGS = 5;

    public ListMultimap groupingSetsByClass;
    public ListMultimap changeLogClassesByName;
    public Map fieldTypesByGroup;
    public final List groups;
    public List groupFields;
    public ListMultimap packageFieldsByPackage;
    public Map groupFieldByPackageField;
    public final Set generatedMethods;
    public Set primaryCallerClasses;
    public Set secondaryCallerClasses;
    public ProgramClass[] programClasses;
    public ClassFileBase[] classFiles;
    public GroupingsSpec groupingsSpec;
    public final ChangeLogMapping changeLogMapping;
    public final ProcessingStatistics processingStatistics;
    public final StaticInitCalleeAnalyzer staticInitCalleeAnalyzer;
    public boolean deriveGroupingsFromChangeLog;
    public final Map fieldPairsByClass;
    public final boolean useFixedSeed;
    public Random random;
    public final NamedSet[] groupingSets;
    public final Map groupsByClass;
    public Object extensionHook;
    public FlowObfuscationManager(
            ProgramClass[] programClasses,
            ClassFileBase[] classFiles,
            ScriptEnvironment scriptEnvironment,
            GroupingsSpec groupingsSpec,
            ChangeLogMapping changeLogMapping,
            ClassMemberLookup classMemberLookup,
            ProcessingStatistics processingStatistics,
            StaticInitCalleeAnalyzer staticInitCalleeAnalyzer,
            boolean deriveGroupingsFromChangeLog,
            boolean useFixedSeed
    ) throws Exception, IOException {
        this.groups = new ArrayList();
        this.groupFields = new ArrayList();
        this.packageFieldsByPackage = new ListMultimap();
        this.groupFieldByPackageField = Utils.createHashMap();
        this.generatedMethods = Utils.createHashSet();
        this.primaryCallerClasses = Utils.createHashSet();
        this.secondaryCallerClasses = Utils.createHashSet();
        this.programClasses = programClasses;
        this.classFiles = classFiles;
        this.groupingsSpec = groupingsSpec;
        this.changeLogMapping = changeLogMapping;
        this.processingStatistics = processingStatistics;
        this.staticInitCalleeAnalyzer = staticInitCalleeAnalyzer;
        this.deriveGroupingsFromChangeLog = deriveGroupingsFromChangeLog;
        this.fieldPairsByClass = Utils.createHashMap(Utils.getPrimeCapacity(classFiles.length));
        this.useFixedSeed = useFixedSeed;

        if (useFixedSeed || HiddenOptionFlags.RANDOMIZE_OBFUSCATION) {
            this.random = Utils.createRandom(128);
        } else {
            this.random = Utils.createSeededRandom(this.programClasses.length);
        }
        this.random.nextBoolean();

        if (!deriveGroupingsFromChangeLog) {
            this.groupingSets = computeGroupingSets(programClasses, classFiles, groupingsSpec, changeLogMapping, classMemberLookup, null);
            this.groupsByClass = buildGroups(programClasses, classFiles, this.groupingSets, this.groups);
        } else {
            if (this.groupingsSpec != null) {
                scriptEnvironment.logWarning(
                        "'deriveGroupingsFromInputChangeLog' specified but 'groupings' statement present. 'groupings' statement will be ignored.");
            }

            if (changeLogMapping == null) {
                scriptEnvironment.logSeriousError_v("'deriveGroupingsFromInputChangeLog' specified but there is no input change log.");
                this.groupingSets = null;
                this.groupsByClass = null;
            } else if (changeLogMapping.hasTraceBackEntries()) {
                this.groupingSets = deriveGroupingSetsFromChangeLog(changeLogMapping, null);
                this.groupsByClass = buildGroupsFromChangeLog(programClasses, this.classFiles, changeLogMapping, this.groupingSets, this.groups);
            } else {
                scriptEnvironment.logSeriousError_v(
                        "'deriveGroupingsFromInputChangeLog' specified but input change log '"
                                + changeLogMapping.getChangeLogName()
                                + " has no flow obfuscation data.");
                this.groupingSets = null;
                this.groupsByClass = null;
            }
        }

        for (int i = 0; i < 5; i++) {
            try {
                Class<?> hookClass = Class.forName(this.getEncodedClassName(i));
                this.extensionHook = hookClass.newInstance();
                break;
            } catch (Throwable ignored) {
            }
        }
    }
    public Random getRandom() {
        return this.random;
    }

    public List getGroups() {
        return this.groups;
    }

    public int getGroupCount() {
        return this.groups.size();
    }

    public int getGroupFieldCount() {
        return this.groupFields.size();
    }

    public Map getGroupsByClass() {
        return this.groupsByClass;
    }

    public FlowFieldPair getFieldPair(Object classFile) {
        return (FlowFieldPair) this.fieldPairsByClass.get(classFile);
    }

    public boolean isAdvancedModeEnabled() {
        return this.processingStatistics.meetsFullSizeThreshold();
    }

    public boolean isGeneratedMethod(Object method) {
        return this.generatedMethods.contains(method);
    }

    public Set getGeneratedMethods() {
        return Utils.createHashSetFrom(this.generatedMethods);
    }

    public boolean isPrimaryCallerClass(Object classFile) {
        return this.primaryCallerClasses.contains(classFile);
    }

    public boolean isSecondaryCallerClass(Object classFile) {
        return this.secondaryCallerClasses.contains(classFile);
    }

    public void addFieldType(Object group, Object fieldType) {
        ((SyncIndexedSet) this.fieldTypesByGroup.get(group)).add(fieldType);
    }

    public void addArrayFieldType(Object group, ClassFileBase classFile) {
        String arrayType = "[L" + classFile.getClassName() + ";";
        ((SyncIndexedSet) this.fieldTypesByGroup.get(group)).add(arrayType);
    }

    public String pickRandomFieldType(Object group, Random rng) {
        SyncIndexedSet types = (SyncIndexedSet) this.fieldTypesByGroup.get(group);
        return (String) types.getElementAt(rng.nextInt(types.size()));
    }

    public ListMultimap getPackageFieldsByPackage() {
        ListMultimap result = new ListMultimap(this.packageFieldsByPackage.getKeyCount());
        TwoKeyMap seen = new TwoKeyMap();

        for (Object value : this.fieldPairsByClass.values()) {
            FlowFieldPair pair = (FlowFieldPair) value;
            String packageName = pair.getPackageName();
            OpaquePredicateField packageField = pair.getPackageField();
            if (seen.putValue(packageName, packageField, packageField) == null) {
                result.addValue(packageName, packageField);
            }
        }

        return result;
    }

    public Set getFieldOwnerClasses() {
        HashSet owners = Utils.createHashSet();
        for (Object entry : this.fieldPairsByClass.entrySet()) {
            FlowFieldPair pair = (FlowFieldPair) ((Entry) entry).getValue();
            owners.add(pair.getGroupField().getOwnerClass());
            owners.add(pair.getPackageField().getOwnerClass());
        }
        return owners;
    }

    public Set getAllPairFields() {
        HashSet fields = Utils.createHashSet();
        for (Object entry : this.fieldPairsByClass.entrySet()) {
            FlowFieldPair pair = (FlowFieldPair) ((Entry) entry).getValue();
            fields.add(pair.getGroupField());
            fields.add(pair.getPackageField());
        }
        return fields;
    }

    public List getGroupFieldsInUse() {
        HashSet fields = Utils.createHashSet();
        for (Object value : this.fieldPairsByClass.values()) {
            fields.add(((FlowFieldPair) value).getGroupField());
        }
        return new ArrayList(fields);
    }

    public boolean hasNonZeroValuedField() {
        for (Object entry : this.fieldPairsByClass.entrySet()) {
            FlowFieldPair pair = (FlowFieldPair) ((Entry) entry).getValue();
            if (pair.getGroupField().isNonZeroValue() || pair.getPackageField().isNonZeroValue()) {
                return true;
            }
        }
        return false;
    }

    public List getGroupingNamesWithoutField() {
        HashSet allNames = Utils.createHashSet();
        HashSet namesWithField = Utils.createHashSet();

        for (Object o : this.groups) {
            FlowObfuscationGroup group = (FlowObfuscationGroup) o;
            List names = group.getGroupingSetNames();
            allNames.addAll(names);
            if (group.getGroupField() != null) {
                namesWithField.addAll(names);
            }
        }

        allNames.removeAll(namesWithField);
        ArrayList result = new ArrayList(allNames);
        Collections.sort(result);
        return result;
    }

    private static String entryKindLabel(boolean traceBack) {
        return traceBack ? "TraceBackClass:" : "ForwardClass:";
    }
    public static void indexGroupsByClass(List groups, Map groupsByClass) {
        for (Object o : groups) {
            FlowObfuscationGroup group = (FlowObfuscationGroup) o;
            group.collectPackageNames();
            for (Object member : group.getMemberClasses()) {
                groupsByClass.put((ClassFileBase) member, group);
            }
        }
    }

    public static HashMap buildGroupsFromChangeLog(
            ProgramClass[] programClasses, ClassFileBase[] classFiles, ChangeLogMapping changeLogMapping, NamedSet[] namedSets, List groups
    ) throws ProcessingException, IOException {
        HashMap groupsByClass = Utils.createHashMap(Utils.getPrimeCapacity(classFiles.length));

        for (NamedSet namedSet : namedSets) {
            groups.add(new FlowObfuscationGroup(new ClassGroupingSet(namedSet)));
        }

        indexGroupsByClass(groups, groupsByClass);

        for (ProgramClass programClass : programClasses) {
            String className = programClass.getClassName();
            if (!changeLogMapping.hasClassMapping(className)) {
                throw new ProcessingException(
                        "'deriveGroupingsFromInputChangeLog' specified but opened class '"
                                + Utils.slashesToDots(className)
                                + "' does not appear in log '"
                                + changeLogMapping.getChangeLogName()
                                + "'");
            }
        }

        return groupsByClass;
    }

    public static HashMap buildGroups(ProgramClass[] programClasses, ClassFileBase[] classFiles, NamedSet[] namedSets, List groups)
            throws Exception, IOException {
        int setCount = namedSets.length;
        HashSet overlappingSets = Utils.createHashSet();
        HashSet overlapCombos = Utils.createHashSet();

        // Find classes that belong to more than one grouping set.
        for (ProgramClass programClass : programClasses) {
            if (programClass.isInterface() && !programClass.supportsJava8()) {
                continue;
            }

            LinkedHashSet containing = new LinkedHashSet();
            for (NamedSet namedSet : namedSets) {
                if (namedSet.contains(programClass)) {
                    containing.add(new IdentityValueHolder(namedSet));
                }
            }

            if (containing.size() > 1) {
                HashSet combo = Utils.createHashSet();
                for (Object o : containing) {
                    IdentityValueHolder holder = (IdentityValueHolder) o;
                    combo.add(holder.getValue());
                    overlappingSets.add(holder);
                }
                overlapCombos.add(combo);
            }
        }

        // Non-overlapping sets become groupings directly.
        ArrayList groupingSetList = new ArrayList();
        for (NamedSet namedSet : namedSets) {
            if (!overlappingSets.contains(new IdentityValueHolder(namedSet))) {
                groupingSetList.add(new ClassGroupingSet(namedSet));
            }
        }

        // Drop combos that are strict subsets of a larger combo.
        ArrayList sortedCombos = new ArrayList(overlapCombos);
        Collections.sort(sortedCombos, (a, b) -> ((HashSet) a).size() - ((HashSet) b).size());

        Iterator comboIterator = sortedCombos.iterator();
        while (comboIterator.hasNext()) {
            HashSet combo = (HashSet) comboIterator.next();
            boolean isSubsumed = false;

            for (int i = sortedCombos.size() - 1; i >= 0; i--) {
                HashSet other = (HashSet) sortedCombos.get(i);
                if (other.size() <= combo.size()) {
                    break;
                }
                if (other.containsAll(combo)) {
                    isSubsumed = true;
                    break;
                }
            }

            if (isSubsumed) {
                overlapCombos.remove(combo);
                comboIterator.remove();
            }
        }

        // Merge overlapping sets into combined groupings.
        for (Object o : overlapCombos) {
            HashSet combo = (HashSet) o;
            NamedSet[] comboSets = (NamedSet[]) combo.toArray(new NamedSet[combo.size()]);
            ClassGroupingSet merged = new ClassGroupingSet(comboSets[0]);
            for (int i = 1; i < comboSets.length; i++) {
                merged = merged.mergeIfOverlapping(new ClassGroupingSet(comboSets[i]));
            }
            groupingSetList.add(merged);
        }

        Collections.sort(groupingSetList);
        int groupingCount = groupingSetList.size();

        for (Object o : groupingSetList) {
            groups.add(new FlowObfuscationGroup((ClassGroupingSet) o));
        }

        // Resolve classes shared between groups so each class is in exactly one group.
        for (int i = groupingCount - 1; i >= 0; i--) {
            ClassGroupingSet higher = (ClassGroupingSet) groupingSetList.get(i);

            for (int j = i - 1; j >= 0; j--) {
                ClassGroupingSet lower = (ClassGroupingSet) groupingSetList.get(j);
                NamedSet sharedSets = higher.getSharedSets(lower);
                if (sharedSets.size() <= 0) {
                    continue;
                }

                NamedSet sharedClasses = Utils.createNamedSet();
                for (Object s : sharedSets) {
                    sharedClasses.addAll((Collection) s);
                }

                NamedSet lowerOnlySets = lower.getSetsNotIn(higher);

                for (Object c : sharedClasses) {
                    ClassFileBase classFile = (ClassFileBase) c;
                    boolean inLowerOnly = false;
                    for (Object s : lowerOnlySets) {
                        if (((NamedSet) s).contains(classFile)) {
                            inLowerOnly = true;
                        }
                    }

                    if (inLowerOnly) {
                        ((FlowObfuscationGroup) groups.get(i)).removeMemberClass(classFile);
                    } else {
                        ((FlowObfuscationGroup) groups.get(j)).removeMemberClass(classFile);
                    }
                }
            }
        }

        HashMap groupsByClass = Utils.createHashMap(Utils.getPrimeCapacity(classFiles.length));
        indexGroupsByClass(groups, groupsByClass);
        return groupsByClass;
    }

    public static ArrayList buildFlowGroups(
            ProgramClass[] programClasses,
            ClassFileBase[] classFiles,
            Map classRenames,
            ScriptEnvironment scriptEnvironment,
            GroupingsSpec groupingsSpec,
            ChangeLogMapping changeLogMapping,
            ClassHierarchyQuery hierarchyQuery,
            boolean deriveFromChangeLog,
            ObservableHolder groupsByClassHolder
    ) throws Exception, IOException {
        HashMap groupsByClass = null;
        ArrayList groups = new ArrayList();

        if (!deriveFromChangeLog) {
            NamedSet[] sets = computeGroupingSets(programClasses, classFiles, groupingsSpec, changeLogMapping, hierarchyQuery, classRenames);
            groupsByClass = buildGroups(programClasses, classFiles, sets, groups);
        } else {
            if (groupingsSpec != null) {
                scriptEnvironment.logWarning(
                        "'deriveGroupingsFromInputChangeLog' specified but 'groupings' statement present. 'groupings' statement will be ignored.");
            }

            if (changeLogMapping == null) {
                scriptEnvironment.logSeriousError_v("'deriveGroupingsFromInputChangeLog' specified but there is no input change log.");
            } else if (changeLogMapping.hasTraceBackEntries()) {
                NamedSet[] sets = deriveGroupingSetsFromChangeLog(changeLogMapping, classRenames);
                groupsByClass = buildGroupsFromChangeLog(programClasses, classFiles, changeLogMapping, sets, groups);
            } else {
                scriptEnvironment.logSeriousError_v(
                        "'deriveGroupingsFromInputChangeLog' specified but input change log '"
                                + changeLogMapping.getChangeLogName()
                                + " has no flow obfuscation data.");
            }
        }

        groupsByClassHolder.setValue(groupsByClass);
        return groups;
    }

    public static NamedSet[] computeGroupingSets(
            ProgramClass[] programClasses,
            ClassFileBase[] classFiles,
            GroupingsSpec groupingsSpec,
            ChangeLogMapping changeLogMapping,
            ClassHierarchyQuery hierarchyQuery,
            Map classRenames
    ) throws Exception, IOException {
        TwoKeyMap setsByName = new TwoKeyMap();

        // One set per input archive (or "FILE SYSTEM" for loose files).
        for (ProgramClass programClass : programClasses) {
            if ((!programClass.isInterface() || programClass.supportsJava8()) && !programClass.isGenerated()) {
                Enumeration locations = programClass.enumerateInputLocations();
                while (locations.hasMoreElements()) {
                    InputFileLocation location = (InputFileLocation) locations.nextElement();
                    if (location.isPlainFile()) {
                        setsByName.putValue("FILE SYSTEM", programClass, programClass);
                    } else {
                        SourceArchive archive = location.getSourceArchive();
                        setsByName.putValue(archive.getQualifiedPath(), programClass, programClass);
                    }
                }
            }
        }

        // User-specified groupings.
        if (groupingsSpec != null) {
            ReadOnlyMultiMap groupedClasses = groupingsSpec.getGroupedClasses();
            ArrayList groupingNames = new ArrayList();
            Enumeration keys = groupedClasses.keys();
            while (keys.hasMoreElements()) {
                groupingNames.add(keys.nextElement());
            }

            for (Object nameObj : groupingNames) {
                String groupingName = (String) nameObj;
                EnumerableMap inner = groupedClasses.getInnerMap(groupingName);
                Map classes = inner.copyMap();

                Iterator classIterator = classes.keySet().iterator();
                while (classIterator.hasNext()) {
                    ProgramClass programClass = (ProgramClass) classIterator.next();
                    if (programClass.isInterface() && !programClass.supportsJava8()) {
                        classIterator.remove();
                    }
                }

                if (classes.size() > 0) {
                    setsByName.putInnerMap(groupingName, classes);
                }
            }

            if (groupingsSpec.isLoggingEnabled()) {
                groupingsSpec.printGroupingParameters();
                Collections.sort(groupingNames);
                PrintWriter writer = groupingsSpec.getLogWriter();
                writer.println("\tMatched groupings:");

                for (Object nameObj : groupingNames) {
                    String groupingName = (String) nameObj;
                    writer.println("\tGrouping \"" + groupingName + "\"");

                    EnumerableMap inner = groupedClasses.getInnerMap(groupingName);
                    ArrayList labeled = new ArrayList();
                    Enumeration classKeys = inner.keys();
                    while (classKeys.hasMoreElements()) {
                        ProgramClass programClass = (ProgramClass) classKeys.nextElement();
                        labeled.add(new LabeledTuple(programClass.getDottedClassName(), programClass));
                    }
                    Collections.sort(labeled);

                    for (Object t : labeled) {
                        LabeledTuple tuple = (LabeledTuple) t;
                        writer.println("\t\t" + AbstractExclusionSpec.formatClassWithModifiers((ClassFileBase) tuple.getFirst(), hierarchyQuery));
                    }
                }
            }
        }

        // Sets derived from a previous change log go first in the result array.
        NamedSet[] result;
        if (changeLogMapping != null && classFiles.length > programClasses.length) {
            NamedSet[] fromChangeLog = deriveGroupingSetsFromChangeLog(changeLogMapping, classRenames);
            result = new NamedSet[fromChangeLog.length + setsByName.getKeyCount()];
            System.arraycopy(fromChangeLog, 0, result, setsByName.getKeyCount(), fromChangeLog.length);
        } else {
            result = new NamedSet[setsByName.getKeyCount()];
        }

        int index = 0;
        Enumeration names = setsByName.keys();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            Map classes = setsByName.getInnerMap(name);
            result[index++] = Utils.createNamedSetFromMap(name, classes);
        }

        return result;
    }

    public static NamedSet[] deriveGroupingSetsFromChangeLog(ChangeLogMapping changeLogMapping, Map classRenames) {
        Map memberEntries = changeLogMapping.getMemberClassEntries();
        SetMultiMap classesByEntry = new SetMultiMap(memberEntries.size());

        for (Object o : memberEntries.entrySet()) {
            Entry entry = (Entry) o;
            String internalName = Utils.dotsToSlashes((String) entry.getKey());
            ObjectPair pair = (ObjectPair) entry.getValue();
            ChangeLogMemberEntry traceBackEntry = (ChangeLogMemberEntry) pair.getFirst();
            classesByEntry.addValue(traceBackEntry, internalName);
        }

        ArrayList result = new ArrayList(classesByEntry.getKeyCount());

        for (Object o : classesByEntry.entrySet()) {
            Entry entry = (Entry) o;
            ChangeLogMemberEntry memberEntry = (ChangeLogMemberEntry) entry.getKey();
            Set classNames = (Set) entry.getValue();
            ArrayList classes = new ArrayList(classNames.size());

            for (Object nameObj : classNames) {
                String oldName = (String) nameObj;
                String currentName = (String) Utils.mapOrSelf(oldName, classRenames);
                ClassFileBase classFile = ClassHierarchyNode.findClassFile(currentName);
                Assert.assertNotNullMessage(classFile, new String[]{oldName, ", ", currentName});
                if (!classFile.isInterface() || classFile.supportsJava8()) {
                    classes.add(classFile);
                }
            }

            if (classes.size() > 0) {
                String setName = memberEntry.getInternalClassName() + "." + memberEntry.getFieldName();
                result.add(Utils.createNamedSet(setName, classes));
            }
        }

        return (NamedSet[]) result.toArray(new NamedSet[result.size()]);
    }

    public boolean isFieldClassInAllGroupings(Object classFile, OpaquePredicateField field) {
        ClassFileBase fieldOwner = ClassHierarchyNode.findClassFile(field.getOwnerClassName());

        if (this.groupingSetsByClass == null) {
            this.groupingSetsByClass = new ListMultimap(this.classFiles.length);
            for (NamedSet set : this.groupingSets) {
                for (Object member : set) {
                    this.groupingSetsByClass.addValue(member, set);
                }
            }
        }

        List setsOfClass = this.groupingSetsByClass.getValues(classFile);
        if (setsOfClass != null) {
            for (Object s : setsOfClass) {
                if (!((NamedSet) s).contains(fieldOwner)) {
                    return false;
                }
            }
        }
        return true;
    }

    public Map createFieldTypeSets() {
        HashMap typesByGroup = Utils.createHashMap(Utils.getPrimeCapacity(this.groups.size()));
        SyncIndexedSet baseTypes = new SyncIndexedSet();

        if (HiddenOptionFlags.OBJECT_OPAQUE_PREDICATE_TYPES) {
            baseTypes.add("Ljava/lang/String;");
            baseTypes.add("[I");
            baseTypes.add("[Ljava/lang/String;");
        } else {
            baseTypes.add("I");
            baseTypes.add("Z");
            if (this.isAdvancedModeEnabled() && !HiddenOptionFlags.NO_STRING_OPAQUE_PREDICATES) {
                baseTypes.add("Ljava/lang/String;");
                baseTypes.add("[I");
                baseTypes.add("[Ljava/lang/String;");
            }
        }

        for (Object o : this.groups) {
            typesByGroup.put(o, new SyncIndexedSet(baseTypes));
        }
        return typesByGroup;
    }

    // =====================================================================
    // Predicate field assignment
    // =====================================================================

    public SetMultiMap assignPredicateFields(
            HashSet packageNames,
            NameExclusionSet nameExclusionSet,
            ClassHierarchy classHierarchy,
            InheritedMemberAnalyzer inheritedMemberAnalyzer,
            ClassMemberLookup classMemberLookup,
            FlowObfuscationExclusions flowObfuscationExclusions,
            ClassInitOrderHandler classInitOrderHandler
    ) throws Exception, IOException {
        if (this.extensionHook != null) {
            try {
                Class<?> hookClass = this.extensionHook.getClass();
                Method hookMethod = hookClass.getDeclaredMethod(this.getEncodedClassName(0));
                if (hookMethod != null) {
                    hookMethod.invoke(null);
                }
            } catch (Throwable ignored) {
            }
        }

        SetMultiMap fieldSignaturesByClass = new SetMultiMap();

        if (this.changeLogMapping != null) {
            ArrayList oldClassNames = this.changeLogMapping.getOldClassNames();
            for (Object name : oldClassNames) {
                packageNames.add(ClassFileBase.getPackagePath(Utils.dotsToSlashes((String) name)));
            }
        }

        int packageCount = packageNames.size();
        int classCount = this.programClasses.length;
        CountingBag referenceCounts = new CountingBag(classCount);
        CountingBag subtreeCounts = new CountingBag(1);

        for (ProgramClass programClass : this.programClasses) {
            programClass.countReferencedProgramClasses(referenceCounts);
        }

        List topNodes = classHierarchy.getTopProgramNodes();
        for (Object node : topNodes) {
            ((ClassHierarchyNode) node).sumSubtreeCounts(new MutableInt(0), new MutableInt(0), referenceCounts, subtreeCounts);
        }

        TwoKeyMap predicateFieldsByClass = new TwoKeyMap();
        this.fieldTypesByGroup = this.createFieldTypeSets();

        if (this.changeLogMapping != null) {
            this.restoreChangeLogFields(
                    packageNames,
                    referenceCounts,
                    nameExclusionSet,
                    flowObfuscationExclusions,
                    classInitOrderHandler,
                    this.random,
                    predicateFieldsByClass,
                    fieldSignaturesByClass,
                    inheritedMemberAnalyzer,
                    classMemberLookup);
        }

        for (Object g : this.groups) {
            FlowObfuscationGroup group = (FlowObfuscationGroup) g;

            // Reuse group field restored from the change log, if any.
            for (Object f : this.groupFields) {
                OpaquePredicateField field = (OpaquePredicateField) f;
                ClassFileBase owner = ClassHierarchyNode.findClassFile(field.getOwnerClassName());
                if (group.isCommonClass(owner)) {
                    group.setGroupField(field);
                    break;
                }
            }

            // Reuse package fields restored from the change log, if any.
            for (Object p : group.getSortedPackageNames()) {
                String packageName = (String) p;
                List candidates = this.packageFieldsByPackage.getValues(packageName);
                if (candidates == null) {
                    continue;
                }
                for (Object f : candidates) {
                    OpaquePredicateField field = (OpaquePredicateField) f;
                    ClassFileBase owner = ClassHierarchyNode.findClassFile(field.getOwnerClassName());
                    if (group.isCommonClass(owner)) {
                        group.putPackageField(packageName, field);
                        break;
                    }
                }
            }

            CountingBag groupCounts = Utils.copyCountingBag(referenceCounts);
            groupCounts.retainAll(group.getCommonClasses());
            List sortedCandidates = groupCounts.getSortedByCount();
            Iterator candidateIterator = sortedCandidates.iterator();

            this.assignFieldsFromCandidates(candidateIterator, group, this.random, predicateFieldsByClass, fieldSignaturesByClass,
                    inheritedMemberAnalyzer, this.staticInitCalleeAnalyzer, classMemberLookup, packageCount,
                    flowObfuscationExclusions, classInitOrderHandler, 1);

            if (!group.hasAllFields()) {
                this.assignFieldsFromCandidates(candidateIterator, group, this.random, predicateFieldsByClass, fieldSignaturesByClass,
                        inheritedMemberAnalyzer, this.staticInitCalleeAnalyzer, classMemberLookup, packageCount,
                        flowObfuscationExclusions, classInitOrderHandler, 2);
            }

            if (packageCount == 1 && !group.hasAllFields()) {
                candidateIterator = sortedCandidates.iterator();
                this.assignFieldsFromCandidates(candidateIterator, group, this.random, predicateFieldsByClass, fieldSignaturesByClass,
                        inheritedMemberAnalyzer, this.staticInitCalleeAnalyzer, classMemberLookup, packageCount,
                        flowObfuscationExclusions, classInitOrderHandler, 3);
            }

            OpaquePredicateField groupField = group.getGroupField();
            if (groupField == null) {
                continue;
            }

            if (!group.hasAllFields()) {
                candidateIterator = sortedCandidates.iterator();
                this.assignFieldsFromCandidates(candidateIterator, group, this.random, predicateFieldsByClass, fieldSignaturesByClass,
                        inheritedMemberAnalyzer, this.staticInitCalleeAnalyzer, classMemberLookup, packageCount,
                        flowObfuscationExclusions, classInitOrderHandler, 4);
            }

            // Last resort: host all remaining package fields in the group field's class.
            if (!group.hasAllFields()) {
                ClassFileBase groupFieldOwner = ClassHierarchyNode.findClassFile(groupField.getOwnerClassName());
                if (groupFieldOwner.isProgramClass()) {
                    for (Object p : group.getSortedPackageNames()) {
                        String packageName = (String) p;
                        if (group.getPackageField(packageName) == null) {
                            OpaquePredicateField packageField = this.createPredicateField(
                                    (ProgramClass) groupFieldOwner, inheritedMemberAnalyzer, classMemberLookup, this.random);
                            this.packageFieldsByPackage.addValue(packageName, packageField);
                            predicateFieldsByClass.putValue(groupFieldOwner, packageField.getFieldName(), packageField);
                            group.putPackageField(packageName, packageField);
                        }
                    }
                }
            }
        }

        for (Object g : this.groups) {
            FlowObfuscationGroup group = (FlowObfuscationGroup) g;
            OpaquePredicateField groupField = group.getGroupField();
            for (Object pf : group.getPackageFields()) {
                this.groupFieldByPackageField.put((OpaquePredicateField) pf, groupField);
            }
        }

        // Build the per-class field pairs.
        for (ProgramClass programClass : this.programClasses) {
            FlowObfuscationGroup group = (FlowObfuscationGroup) this.groupsByClass.get(programClass);
            if (group == null) {
                continue;
            }

            OpaquePredicateField groupField = group.getGroupField();
            if (groupField != null && !this.fieldPairsByClass.containsKey(programClass)) {
                OpaquePredicateField packageField = group.getPackageField(programClass.getPackagePath());
                this.fieldPairsByClass.put(programClass, new FlowFieldPair(groupField, packageField, programClass.getPackagePath()));
            }

            if (groupField != null && programClass.hasVersionedVariants()) {
                FlowFieldPair pair = (FlowFieldPair) this.fieldPairsByClass.get(programClass);
                for (Object variant : programClass.getVersionedVariants()) {
                    this.fieldPairsByClass.put((ClassFileBase) variant, pair);
                }
            }
        }

        return fieldSignaturesByClass;
    }

    public void assignFieldsFromCandidates(
            Iterator candidates,
            FlowObfuscationGroup group,
            Random rng,
            TwoKeyMap predicateFieldsByClass,
            SetMultiMap fieldSignaturesByClass,
            InheritedMemberAnalyzer inheritedMemberAnalyzer,
            StaticInitCalleeAnalyzer staticInitCalleeAnalyzer,
            ClassMemberLookup classMemberLookup,
            int packageCount,
            FlowObfuscationExclusions flowObfuscationExclusions,
            ClassInitOrderHandler classInitOrderHandler,
            int pass
    ) throws Exception, IOException {
        while (candidates.hasNext() && !group.hasAllFields()) {
            ProgramClass candidate = (ProgramClass) candidates.next();

            boolean passAllowsCandidate = pass != 1 || staticInitCalleeAnalyzer.isInitDependencyLeaf(candidate);
            boolean allowNonPublic = packageCount == 1 && pass != 1 && pass != 2;

            if (!passAllowsCandidate
                    || predicateFieldsByClass.containsKey(candidate)
                    || !this.canHostPredicateField(candidate, flowObfuscationExclusions, classInitOrderHandler, classMemberLookup, allowNonPublic)) {
                continue;
            }

            if (group.getGroupField() == null) {
                if (this.isAdvancedModeEnabled() && !HiddenOptionFlags.NO_STRING_OPAQUE_PREDICATES) {
                    this.addArrayFieldType(group, candidate);
                }

                OpaquePredicateField groupField = this.createPredicateField(candidate, inheritedMemberAnalyzer, classMemberLookup, rng);
                this.groupFields.add(groupField);
                fieldSignaturesByClass.addValue(candidate, groupField.getFieldSignature());
                predicateFieldsByClass.putValue(candidate, groupField.getFieldName(), groupField);
                group.setGroupField(groupField);
                continue;
            }

            boolean needsPackageField = false;
            String targetPackage = null;

            if (pass == 1 || pass == 2 || pass == 3) {
                targetPackage = candidate.getPackagePath();
                if (group.getPackageField(targetPackage) != null) {
                    continue;
                }
                needsPackageField = true;
            } else {
                for (Object p : group.getSortedPackageNames()) {
                    targetPackage = (String) p;
                    if (group.getPackageField(targetPackage) == null) {
                        needsPackageField = true;
                        break;
                    }
                }
            }

            if (needsPackageField) {
                OpaquePredicateField packageField = this.createPredicateField(candidate, inheritedMemberAnalyzer, classMemberLookup, rng);
                this.packageFieldsByPackage.addValue(targetPackage, packageField);
                predicateFieldsByClass.putValue(candidate, packageField.getFieldName(), packageField);
                fieldSignaturesByClass.addValue(candidate, packageField.getFieldSignature());
                group.putPackageField(targetPackage, packageField);
            }
        }
    }

    public boolean canHostPredicateField(
            ProgramClass programClass,
            FlowObfuscationExclusions flowObfuscationExclusions,
            ClassInitOrderHandler classInitOrderHandler,
            ClassMemberLookup classMemberLookup,
            boolean allowNonPublic
    ) throws Exception, IOException {
        String className = programClass.getClassName();
        Set annotations = programClass.getAnnotationTypes();

        return !programClass.isInterface()
                && (programClass.isPublic() || allowNonPublic)
                && !programClass.isMultiRelease()
                && (flowObfuscationExclusions == null || !flowObfuscationExclusions.isExcludedFromPredicateFields(programClass))
                && (classInitOrderHandler == null || !classInitOrderHandler.isLaterInitializedClass(programClass))
                && !classMemberLookup.isSubclass(className, "org/eclipse/osgi/util/NLS")
                && !classMemberLookup.implementsInterface(className, "javax/ejb/EnterpriseBean")
                && (annotations == null
                || (!annotations.contains("javax/ejb/Stateful")
                && !annotations.contains("javax/ejb/Stateless")
                && !annotations.contains("javax/ejb/MessageDriven")));
    }

    public OpaquePredicateField createPredicateField(
            ProgramClass programClass, InheritedMemberAnalyzer inheritedMemberAnalyzer, ClassMemberLookup classMemberLookup, Random rng
    ) throws Exception, IOException {
        FlowObfuscationGroup group = (FlowObfuscationGroup) this.groupsByClass.get(programClass);
        String fieldType = this.pickRandomFieldType(group, rng);

        if (!this.isAdvancedModeEnabled()) {
            FieldInfo field = programClass.createUniquelyNamedStaticField(fieldType, 4, false, inheritedMemberAnalyzer, classMemberLookup, 2);
            return new OpaquePredicateField(field);
        }

        FieldInfo field = programClass.createUniquelyNamedStaticField(fieldType, 1, false, inheritedMemberAnalyzer, classMemberLookup, 2);
        ArrayList newConstants = new ArrayList();
        MethodInfo setter = this.createSetter(programClass, field, newConstants, inheritedMemberAnalyzer, classMemberLookup);
        MethodInfo getter = this.createGetter(programClass, field, newConstants, inheritedMemberAnalyzer, classMemberLookup);
        MethodInfo negatedGetter = null;
        if (fieldType.equals("I") || fieldType.equals("Z")) {
            negatedGetter = this.createNegatedGetter(programClass, getter, newConstants, inheritedMemberAnalyzer, classMemberLookup, rng);
        }

        programClass.getClassConstantPool().appendEntries(newConstants);
        return new OpaquePredicateField(field, setter, getter, negatedGetter, rng);
    }

    // =====================================================================
    // Caller method selection
    // =====================================================================

    public void selectCallerMethods(
            Set primaryCallers,
            Set secondaryCallers,
            ListMultimap methodsByClass,
            FlowObfuscationExclusions flowObfuscationExclusions,
            StaticInitCalleeAnalyzer staticInitCalleeAnalyzer
    ) {
        for (Object g : this.groups) {
            FlowObfuscationGroup group = (FlowObfuscationGroup) g;
            if (group.getGroupField() == null) {
                continue;
            }

            ArrayList weightedMethods = new ArrayList(group.getMemberClasses().size());
            for (Object m : group.getMemberClasses()) {
                ClassFileBase classFile = (ClassFileBase) m;
                if (classFile.isProgramClass()) {
                    List methods = methodsByClass.getValues((ProgramClass) classFile);
                    if (methods != null) {
                        weightedMethods.addAll(methods);
                    }
                }
            }

            Collections.sort(weightedMethods);
            Collections.reverse(weightedMethods);

            int packageCount = group.getPackageNames().size();
            HashMap primaryByPackage = Utils.createHashMap(Utils.getPrimeCapacity(packageCount));
            HashMap secondaryByPackage = Utils.createHashMap(primaryByPackage.size());

            for (Object w : weightedMethods) {
                WeightedObject weighted = (WeightedObject) w;
                MethodBytecode bytecode = (MethodBytecode) weighted.value;
                String packagePath = bytecode.getPackagePath();

                boolean allPackagesCovered = packageCount <= primaryByPackage.size() && packageCount <= secondaryByPackage.size();
                if (allPackagesCovered || weighted.weight < 10.0F) {
                    break;
                }

                MethodInfo method = (MethodInfo) bytecode.getMethod();
                boolean eligible = (flowObfuscationExclusions == null || !flowObfuscationExclusions.isMethodExcluded(method))
                        && (staticInitCalleeAnalyzer == null || !staticInitCalleeAnalyzer.isCalledByInitializer(method))
                        && !bytecode.getOwningClass().isMultiRelease()
                        && !bytecode.isStaticInitializer()
                        && !bytecode.isPrivate();

                if (eligible) {
                    if (!primaryByPackage.containsKey(packagePath)) {
                        primaryByPackage.put(packagePath, bytecode);
                    } else if (!secondaryByPackage.containsKey(packagePath)) {
                        secondaryByPackage.put(packagePath, bytecode);
                    }
                }
            }

            for (Object v : primaryByPackage.values()) {
                primaryCallers.add(v);
            }
            for (Object v : secondaryByPackage.values()) {
                secondaryCallers.add(v);
            }
        }

        for (Object o : primaryCallers) {
            this.primaryCallerClasses.add(((MethodBytecode) o).getOwningClass());
        }
        for (Object o : secondaryCallers) {
            this.secondaryCallerClasses.add(((MethodBytecode) o).getOwningClass());
        }
    }

    // =====================================================================
    // Bytecode emission: field initializer / getters / setters
    // =====================================================================

    public static List buildFieldInitializer(
            OpaquePredicateField field,
            List newConstants,
            ConstantPool constantPool,
            boolean useDescriptorForArrayType,
            ClassMemberLookup classMemberLookup,
            ClassResolver classResolver,
            Random rng
    ) throws Exception, IOException {
        ArrayList instructions = new ArrayList();

        if (field.isString()) {
            String value = new IndexedNameGenerator().getNonKeywordName(rng.nextInt(Integer.MAX_VALUE));
            instructions.add(Instruction.createStringConstantLoad(value, constantPool, newConstants));

        } else if (field.isObjectType()) {
            String type = field.getFieldType();
            ResolvedClassConstant classConstant = constantPool.getOrCreateClassConstant(type.substring(1, type.length() - 1), newConstants);
            instructions.add(new TypeInstruction(classConstant));
            instructions.add(SimpleInstruction.forOpcode(OP_DUP));
            ResolvedMethodRefConstant constructor = constantPool.getOrAddMethodRef(
                    classConstant.getClassName(), "<init>", "()V", newConstants, classMemberLookup, classResolver);
            instructions.add(new ConstantRefInstruction(OP_INVOKESPECIAL, constructor));

        } else if (field.isPrimitiveArray()) {
            instructions.add(Instruction.createIntConstantPush(rng.nextInt(5) + 1, constantPool, newConstants));
            String type = field.getFieldType();
            String elementType = type.substring(type.lastIndexOf('[') + 1);
            instructions.add(new NewArrayInstruction(elementType));

        } else if (field.isObjectArray()) {
            instructions.add(Instruction.createIntConstantPush(rng.nextInt(5) + 1, constantPool, newConstants));
            String type = useDescriptorForArrayType ? field.getFieldDescriptor() : field.getFieldType();
            String elementClassName = type.substring(type.lastIndexOf('[') + 2, type.length() - 1);
            ResolvedClassConstant elementClass = constantPool.getOrCreateClassConstant(elementClassName, newConstants);
            instructions.add(new ConstantRefInstruction(OP_ANEWARRAY, elementClass));
        }

        return instructions;
    }

    public void emitGetterBody(ArrayList out, ClassFileBase owner, AbstractFieldInfo field, List newConstants) {
        String descriptor = field.getDescriptor();
        ResolvedFieldRef fieldRef = owner.getConstantPool()
                .getOrCreateFieldRef(field.getClassName(), field.getSourceName(), descriptor, newConstants, field);
        out.add(new ConstantRefInstruction(OP_GETSTATIC, fieldRef));

        boolean isIntLike = descriptor.equals("I") || descriptor.equals("Z");
        out.add(SimpleInstruction.forOpcode(isIntLike ? OP_IRETURN : OP_ARETURN));
    }

    public void emitSetterBody(ArrayList out, LocalVariableList locals, ClassFileBase owner, AbstractFieldInfo field, List newConstants) {
        String descriptor = field.getDescriptor();
        ResolvedFieldRef fieldRef = owner.getConstantPool()
                .getOrCreateFieldRef(field.getClassName(), field.getSourceName(), descriptor, newConstants, field);

        if (descriptor.equals("I") || descriptor.equals("Z")) {
            out.add(Instruction.createIntLoad(0, locals, 2));
        } else {
            out.add(Instruction.createObjectLoad(0, locals, 2));
        }

        out.add(new ConstantRefInstruction(OP_PUTSTATIC, fieldRef));
        out.add(SimpleInstruction.forOpcode(OP_RETURN));
    }

    /**
     * Emits: int v = getter(); if (v != 0) return <truthy>; return 0;
     */
    public void emitNegatedGetterBody(
            ArrayList out, LocalVariableList locals, ClassFileBase owner, AbstractMethodInfo getter, List newConstants, Random rng
    ) {
        ResolvedMethodRefConstant getterRef = owner.getConstantPool().getOrCreateMethodRefConstant(getter, newConstants);
        out.add(new ConstantRefInstruction(OP_INVOKESTATIC, getterRef));
        out.add(Instruction.createIntStore(0, locals, 2));
        out.add(Instruction.createIntLoad(0, locals, 2));

        LabelInstruction skipLabel = new LabelInstruction(true, 1);
        out.add(new BranchInstruction(OP_IFNE, skipLabel));

        if (getter.getDescriptor().equals("()Z")) {
            out.add(SimpleInstruction.forOpcode(OP_ICONST_1));
        } else {
            out.add(Instruction.createIntPush(rng.nextInt(126) + 1));
        }
        out.add(SimpleInstruction.forOpcode(OP_IRETURN));

        out.add(skipLabel);
        out.add(SimpleInstruction.forOpcode(OP_ICONST_0));
        out.add(SimpleInstruction.forOpcode(OP_IRETURN));
    }

    // =====================================================================
    // Method creation (program classes)
    // =====================================================================

    public MethodInfo createSetter(
            ProgramClass owner, FieldInfo field, List newConstants, InheritedMemberAnalyzer analyzer, ClassMemberLookup lookup
    ) throws ProcessingException {
        String descriptor = OpaquePredicateField.setterDescriptorFor(field.getDescriptor());
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitSetterBody(code, locals, owner, field, newConstants);
        MethodInfo method = owner.createUniquelyNamedPublicStaticMethod(
                descriptor, code, 1, locals, new ExceptionHandlerSpec[0], newConstants, analyzer, lookup);
        this.generatedMethods.add(method);
        return method;
    }

    public MethodInfo createGetter(
            ProgramClass owner, FieldInfo field, List newConstants, InheritedMemberAnalyzer analyzer, ClassMemberLookup lookup
    ) throws ProcessingException {
        String descriptor = OpaquePredicateField.getterDescriptorFor(field.getDescriptor());
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitGetterBody(code, owner, field, newConstants);
        MethodInfo method = owner.createUniquelyNamedPublicStaticMethod(
                descriptor, code, 0, locals, new ExceptionHandlerSpec[0], newConstants, analyzer, lookup);
        this.generatedMethods.add(method);
        return method;
    }

    public MethodInfo createNegatedGetter(
            ProgramClass owner, MethodInfo getter, List newConstants, InheritedMemberAnalyzer analyzer, ClassMemberLookup lookup, Random rng
    ) throws ProcessingException {
        String descriptor = getter.getDescriptor();
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitNegatedGetterBody(code, locals, owner, getter, newConstants, rng);
        MethodInfo method = owner.createUniquelyNamedPublicStaticMethod(
                descriptor, code, 1, locals, new ExceptionHandlerSpec[0], newConstants, analyzer, lookup);
        this.generatedMethods.add(method);
        return method;
    }

    public MethodInfo createNamedSetter(
            ProgramClass owner, String name, FieldInfo field, List newConstants, InheritedMemberAnalyzer analyzer, ClassMemberLookup lookup
    ) throws ProcessingException {
        String descriptor = OpaquePredicateField.setterDescriptorFor(field.getDescriptor());
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitSetterBody(code, locals, owner, field, newConstants);
        MethodInfo method = owner.createPublicStaticMethod(
                name, descriptor, code, 1, locals, new ExceptionHandlerSpec[0], newConstants, analyzer, lookup);
        this.generatedMethods.add(method);
        return method;
    }

    public MethodInfo createNamedGetter(
            ProgramClass owner, String name, FieldInfo field, List newConstants, InheritedMemberAnalyzer analyzer, ClassMemberLookup lookup
    ) throws ProcessingException {
        String descriptor = OpaquePredicateField.getterDescriptorFor(field.getDescriptor());
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitGetterBody(code, owner, field, newConstants);
        MethodInfo method = owner.createPublicStaticMethod(
                name, descriptor, code, 0, locals, new ExceptionHandlerSpec[0], newConstants, analyzer, lookup);
        this.generatedMethods.add(method);
        return method;
    }

    public MethodInfo createNamedNegatedGetter(
            ProgramClass owner, String name, MethodInfo getter, List newConstants, InheritedMemberAnalyzer analyzer, ClassMemberLookup lookup, Random rng
    ) throws ProcessingException {
        String descriptor = getter.getDescriptor();
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitNegatedGetterBody(code, locals, owner, getter, newConstants, rng);
        MethodInfo method = owner.createPublicStaticMethod(
                name, descriptor, code, 1, locals, new ExceptionHandlerSpec[0], newConstants, analyzer, lookup);
        this.generatedMethods.add(method);
        return method;
    }

    // =====================================================================
    // Method creation (library classes)
    // =====================================================================

    public LibraryMethod createLibrarySetter(
            ClasspathClassFile owner, String name, LibraryFieldInfo field, List newConstants, InheritedMemberAnalyzer analyzer
    ) throws ProcessingException {
        String descriptor = OpaquePredicateField.setterDescriptorFor(field.getDescriptor());
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitSetterBody(code, locals, owner, field, newConstants);
        return owner.createCodeMethod(name, descriptor, code, 1, locals, new ExceptionHandlerSpec[0], newConstants, analyzer);
    }

    public LibraryMethod createLibraryGetter(
            ClasspathClassFile owner, String name, AbstractFieldInfo field, List newConstants, InheritedMemberAnalyzer analyzer
    ) throws ProcessingException {
        String descriptor = OpaquePredicateField.getterDescriptorFor(field.getDescriptor());
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitGetterBody(code, owner, field, newConstants);
        return owner.createCodeMethod(name, descriptor, code, 0, locals, new ExceptionHandlerSpec[0], newConstants, analyzer);
    }

    public LibraryMethod createLibraryNegatedGetter(
            ClasspathClassFile owner, String name, AbstractMethodInfo getter, List newConstants, InheritedMemberAnalyzer analyzer, Random rng
    ) throws ProcessingException {
        String descriptor = getter.getDescriptor();
        LocalVariableList locals = new LocalVariableList(true, descriptor, LOCALS_FLAGS);
        ArrayList code = new ArrayList();
        this.emitNegatedGetterBody(code, locals, owner, getter, newConstants, rng);
        return owner.createCodeMethod(name, descriptor, code, 1, locals, new ExceptionHandlerSpec[0], newConstants, analyzer);
    }

    // =====================================================================
    // Change-log handling
    // =====================================================================

    public boolean isUsedInEarlierPass(
            ChangeLogMemberEntry entry,
            ClassFileBase classFile,
            InheritedMemberAnalyzer analyzer,
            ObservableHolder errorHolder
    ) throws Exception, IOException {
        if (entry.hasNoField()) {
            return false;
        }

        String descriptor = entry.getFieldDescriptor();
        String typeName = entry.getFieldTypeName();
        String className = entry.getClassName();
        String suffix = "' is associated with a Flow Obfuscation "
                + (entry.isTraceBackEntry() ? "TraceBackClass:" : "ForwardClass:")
                + " but it has been used in an earlier flow obfuscation pass. You have probably used the wrong input change log! Otherwise, you must distribute this application as a whole.";

        Set visibleFields = analyzer.getVisibleFieldSignatures(classFile);
        Set visibleMethods = analyzer.getVisibleMethodNameTypes(classFile);

        if (visibleFields != null && visibleFields.contains(new FieldSignature(entry.getFieldName(), descriptor))) {
            errorHolder.setValue("Field '" + typeName + " " + entry.getFieldName() + "' in class '" + className + suffix);
            return true;
        }

        String setterName = entry.getSetterMethodName();
        String setterDescriptor = OpaquePredicateField.setterDescriptorFor(descriptor);
        if (setterName != null && visibleMethods != null
                && visibleMethods.contains(new FieldNameTypeSignature(setterName, setterDescriptor))) {
            errorHolder.setValue("Method '" + setterName + setterDescriptor + "' in class '" + className + suffix);
            return true;
        }

        String getterDescriptor = OpaquePredicateField.getterDescriptorFor(descriptor);

        String getterName = entry.getGetterMethodName();
        if (getterName != null && visibleMethods != null
                && visibleMethods.contains(new FieldNameTypeSignature(getterName, getterDescriptor))) {
            errorHolder.setValue("Method '" + getterName + getterDescriptor + "' in class '" + className + suffix);
            return true;
        }

        String altGetterName = entry.getAltGetterMethodName();
        if (altGetterName != null && visibleMethods != null
                && visibleMethods.contains(new FieldNameTypeSignature(altGetterName, getterDescriptor))) {
            errorHolder.setValue("Method '" + altGetterName + getterDescriptor + "' in class '" + className + suffix);
            return true;
        }

        return false;
    }

    public CountingBag findCandidateClasses(Object internalClassName, CountingBag referenceCounts, ChangeLogMapping changeLogMapping) {
        if (this.changeLogClassesByName == null) {
            this.changeLogClassesByName = new ListMultimap();
            Map memberEntries = changeLogMapping.getMemberClassEntries();

            for (Object o : memberEntries.entrySet()) {
                Entry entry = (Entry) o;
                String internalName = Utils.dotsToSlashes((String) entry.getKey());
                ProgramClass programClass = ClassHierarchyNode.findProgramClass(internalName);
                if (programClass != null) {
                    ObjectPair pair = (ObjectPair) entry.getValue();
                    ChangeLogMemberEntry first = (ChangeLogMemberEntry) pair.getFirst();
                    ChangeLogMemberEntry second = (ChangeLogMemberEntry) pair.getSecond();
                    this.changeLogClassesByName.addValue(first.getInternalClassName(), programClass);
                    this.changeLogClassesByName.addValue(second.getInternalClassName(), programClass);
                }
            }
        }

        List classesForName = this.changeLogClassesByName.getValues(internalClassName);

        if (classesForName != null && classesForName.size() > 0) {
            HashSet groupsWithCommonClass = Utils.createHashSet(7);
            HashSet groupsContainingAll = Utils.createHashSet(7);

            for (Object g : this.groups) {
                FlowObfuscationGroup group = (FlowObfuscationGroup) g;
                boolean containsAll = true;
                boolean hasCommon = false;

                for (Object c : classesForName) {
                    ProgramClass programClass = (ProgramClass) c;
                    if (!group.containsClass(programClass)) {
                        containsAll = false;
                        break;
                    }
                    if (group.isCommonClass(programClass)) {
                        hasCommon = true;
                    }
                }

                if (containsAll) {
                    groupsContainingAll.add(group);
                    if (hasCommon) {
                        groupsWithCommonClass.add(group);
                    }
                }
            }

            FlowObfuscationGroup chosen = null;
            if (groupsWithCommonClass.size() == 1) {
                chosen = (FlowObfuscationGroup) groupsWithCommonClass.iterator().next();
            } else if (groupsContainingAll.size() == 1) {
                chosen = (FlowObfuscationGroup) groupsContainingAll.iterator().next();
            }

            if (chosen == null) {
                return null;
            }

            CountingBag result = Utils.copyCountingBag(referenceCounts);
            result.retainAll(chosen.getCommonClasses());
            return result;
        }

        if (this.changeLogClassesByName.getKeyCount() == 0 && this.groups.size() == 1) {
            FlowObfuscationGroup onlyGroup = (FlowObfuscationGroup) this.groups.get(0);
            CountingBag result = Utils.copyCountingBag(referenceCounts);
            result.retainAll(onlyGroup.getCommonClasses());
            return result;
        }

        return null;
    }

    public ClassFileBase findLibraryClass(Object internalName, SetMultiMap classesByName) {
        Set classes = classesByName.getValues(internalName);
        if (classes != null) {
            for (Object c : classes) {
                ClassFileBase classFile = (ClassFileBase) c;
                if (!classFile.isProgramClass()) {
                    return classFile;
                }
            }
        }
        return null;
    }

    public OpaquePredicateField createLibraryPredicateField(
            ChangeLogMemberEntry entry, ClasspathClassFile libraryClass, InheritedMemberAnalyzer analyzer
    ) throws Exception, IOException {
        FlowObfuscationGroup group = (FlowObfuscationGroup) this.groupsByClass.get(libraryClass);
        String descriptor = entry.getFieldDescriptor();
        this.addFieldType(group, descriptor);
        libraryClass.getClassName();

        LibraryFieldInfo field = (LibraryFieldInfo) libraryClass.findField(entry.getFieldName(), descriptor);
        if (field == null) {
            field = libraryClass.createField(entry.getFieldName(), descriptor, entry.hasSetterMethod() ? 1 : 4);
            analyzer.addField(field);
        }

        if (!entry.hasSetterMethod()) {
            return new OpaquePredicateField(field);
        }

        ArrayList newConstants = new ArrayList();

        AbstractMethodInfo setter = libraryClass.findMethod(
                new MethodSignature(entry.getSetterMethodName(), OpaquePredicateField.setterDescriptorFor(descriptor)));
        if (setter == null) {
            setter = this.createLibrarySetter(libraryClass, entry.getSetterMethodName(), field, newConstants, analyzer);
        }

        AbstractMethodInfo getter = libraryClass.findMethod(
                new MethodSignature(entry.getGetterMethodName(), OpaquePredicateField.getterDescriptorFor(descriptor)));
        if (getter == null) {
            getter = this.createLibraryGetter(libraryClass, entry.getGetterMethodName(), field, newConstants, analyzer);
        }

        AbstractMethodInfo negatedGetter = null;
        if (descriptor.equals("I") || descriptor.equals("Z")) {
            negatedGetter = libraryClass.findMethod(
                    new MethodSignature(entry.getAltGetterMethodName(), OpaquePredicateField.getterDescriptorFor(descriptor)));
            if (negatedGetter == null) {
                negatedGetter = this.createLibraryNegatedGetter(
                        libraryClass, entry.getAltGetterMethodName(), getter, newConstants, analyzer, this.random);
            }
        }

        libraryClass.getConstantPool().appendEntries(newConstants);
        return new OpaquePredicateField(field, setter, getter, negatedGetter, entry.isAlternateVariant());
    }

    public OpaquePredicateField createPredicateFieldFromChangeLog(
            ChangeLogMemberEntry entry,
            ProgramClass programClass,
            InheritedMemberAnalyzer analyzer,
            ClassMemberLookup lookup,
            Random rng
    ) throws Exception, IOException {
        FlowObfuscationGroup group = (FlowObfuscationGroup) this.groupsByClass.get(programClass);
        String descriptor = entry.getFieldDescriptor();
        this.addFieldType(group, descriptor);

        FieldInfo field = programClass.createStaticField(
                entry.getFieldName(), descriptor, entry.hasSetterMethod() ? 1 : 4, analyzer, lookup);

        if (!entry.hasSetterMethod()) {
            return new OpaquePredicateField(field);
        }

        ArrayList newConstants = new ArrayList();
        MethodInfo setter = this.createNamedSetter(programClass, entry.getSetterMethodName(), field, newConstants, analyzer, lookup);
        MethodInfo getter = this.createNamedGetter(programClass, entry.getGetterMethodName(), field, newConstants, analyzer, lookup);

        MethodInfo negatedGetter = null;
        String altGetterName = entry.getAltGetterMethodName();
        if ((descriptor.equals("I") || descriptor.equals("Z")) && altGetterName != null) {
            negatedGetter = this.createNamedNegatedGetter(programClass, altGetterName, getter, newConstants, analyzer, lookup, rng);
        }

        programClass.getClassConstantPool().appendEntries(newConstants);
        return new OpaquePredicateField(field, setter, getter, negatedGetter, entry.isAlternateVariant());
    }

    public OpaquePredicateField getOrCreateChangeLogField(
            ChangeLogMemberEntry entry,
            ClassFileBase classFile,
            ChangeLogMapping changeLogMapping,
            Random rng,
            TwoKeyMap predicateFieldsByClass,
            Map fieldRenames,
            TwoKeyMap methodRenames,
            InheritedMemberAnalyzer analyzer,
            ClassMemberLookup lookup
    ) throws Exception, IOException {
        OpaquePredicateField result = null;
        String fieldName = entry.getFieldName();
        String descriptor = entry.getFieldDescriptor();
        String typeName = entry.getFieldTypeName();
        String className = classFile.getClassName();

        if (entry.hasNoField()) {
            if (classFile.isProgramClass()) {
                result = this.createPredicateField((ProgramClass) classFile, analyzer, lookup, rng);
                predicateFieldsByClass.putValue(classFile, result.getFieldName(), result);
            } else {
                changeLogMapping.reportFatalError(
                        "Class '"
                                + classFile.getDottedClassName()
                                + "' appears in the change log flow obfuscation data but has not been opened for obfuscation yet its flow obfuscation data is incomplete.  For incremental obfuscation, the flow data must be complete.");
            }
            return result;
        }

        if (!classFile.isProgramClass()) {
            result = (OpaquePredicateField) predicateFieldsByClass.getValue(classFile, fieldName);
            if (result == null) {
                result = this.createLibraryPredicateField(entry, (ClasspathClassFile) classFile, analyzer);
            }
            return result;
        }

        result = (OpaquePredicateField) predicateFieldsByClass.getValue(classFile, fieldName);

        if (result == null) {
            if (this.isUsedInEarlierPass(entry, classFile, analyzer, new ObservableHolder())) {
                // A fresh field has to be generated; record the renames so the change log stays consistent.
                result = this.createPredicateField((ProgramClass) classFile, analyzer, lookup, rng);
                fieldRenames.put(new Triple(className, fieldName, typeName), result.getFieldName());

                if (entry.hasSetterMethod()) {
                    String ownerName = classFile.getClassName();
                    methodRenames.putValue(ownerName,
                            new Triple(entry.getSetterMethodName(), entry.getFieldTypeName(), "void"),
                            result.getSetterName());
                    methodRenames.putValue(ownerName,
                            new Triple(entry.getGetterMethodName(), "", entry.getFieldTypeName()),
                            result.getGetterName());
                    if (entry.getNewAltGetterMethodName() != null) {
                        methodRenames.putValue(ownerName,
                                new Triple(entry.getAltGetterMethodName(), "", entry.getFieldTypeName()),
                                result.getNegatedGetterName());
                    }
                }
            } else {
                result = this.createPredicateFieldFromChangeLog(entry, (ProgramClass) classFile, analyzer, lookup, rng);
            }

            predicateFieldsByClass.putValue(classFile, result.getFieldName(), result);

        } else if (descriptor != null && !result.getFieldType().equals(descriptor)) {
            changeLogMapping.logError(
                    "The field '"
                            + fieldName
                            + "' in class '"
                            + classFile.getDottedClassName()
                            + "' appears in the change log more than once but with different types.  You must distribute this application as a whole.");
        }

        return result;
    }

    public boolean hasExcludedChangeLogMembers(
            ChangeLogMemberEntry entry,
            ClassFileBase classFile,
            TwoKeyMap excludedFields,
            Map excludedMethods,
            NameExclusionSet nameExclusionSet,
            ClassMemberLookup lookup,
            ObservableHolder errorHolder
    ) throws Exception, IOException {
        String fieldName = entry.getFieldName();
        if (fieldName == null) {
            return false;
        }

        boolean excluded = false;
        String internalName = entry.getInternalClassName();
        String displayName = entry.getClassName();
        String typeName = entry.getFieldTypeName();
        String descriptor = entry.getFieldDescriptor();
        String kind = entryKindLabel(entry.isTraceBackEntry());
        String prefix = "Class '" + displayName + "' appears as a Flow Obfuscation " + kind
                + " but it is now incompatible. You must distribute this application as a whole. : ";

        FieldInfo field = null;
        if (classFile.isProgramClass()) {
            field = lookup.findField(internalName, entry.getNewFieldName(), descriptor);
        }
        if (field != null && field.isProgramMember() && nameExclusionSet.isFieldExcluded(field)) {
            errorHolder.setValue(prefix + field.toDisplayString());
            ObjectPair key = new ObjectPair(fieldName, typeName);
            excludedFields.putValue(internalName, key, key);
            excluded = true;
        }

        if (entry.getSetterMethodName() != null) {
            MethodInfo setter = null;
            if (classFile.isProgramClass()) {
                setter = lookup.findDeclaredMethod(
                        (ProgramClass) classFile,
                        new MethodSignature(entry.getNewSetterMethodName(), OpaquePredicateField.setterDescriptorFor(descriptor)));
            }
            if (setter != null && setter.isProgramMember() && nameExclusionSet.isMethodExcluded(setter)) {
                errorHolder.setValue(prefix + setter.toDisplayString() + " (A)");
                excludedMethods.put(internalName, new Triple(entry.getSetterMethodName(), typeName, "void"));
                excluded = true;
            }
        }

        if (entry.getGetterMethodName() != null) {
            MethodInfo getter = null;
            if (classFile.isProgramClass()) {
                getter = lookup.findDeclaredMethod(
                        (ProgramClass) classFile,
                        new MethodSignature(entry.getNewGetterMethodName(), OpaquePredicateField.getterDescriptorFor(descriptor)));
            }
            if (getter != null && getter.isProgramMember() && nameExclusionSet.isMethodExcluded(getter)) {
                errorHolder.setValue(prefix + getter.toDisplayString() + " (B)");
                excludedMethods.put(internalName, new Triple(entry.getGetterMethodName(), "", typeName));
                excluded = true;
            }
        }

        if (entry.getAltGetterMethodName() != null) {
            MethodInfo altGetter = null;
            if (classFile.isProgramClass()) {
                altGetter = lookup.findDeclaredMethod(
                        (ProgramClass) classFile,
                        new MethodSignature(entry.getNewAltGetterMethodName(), OpaquePredicateField.getterDescriptorFor(descriptor)));
            }
            if (altGetter != null && altGetter.isProgramMember() && nameExclusionSet.isMethodExcluded(altGetter)) {
                errorHolder.setValue(prefix + altGetter.toDisplayString() + " (C)");
                excludedMethods.put(internalName, new Triple(entry.getAltGetterMethodName(), "", typeName));
                excluded = true;
            }
        }

        return excluded;
    }

    public ProgramClass findHostClassForChangeLogEntry(
            ChangeLogMemberEntry entry,
            CountingBag referenceCounts,
            Map hostClassByOldName,
            ChangeLogMapping changeLogMapping,
            NameExclusionSet nameExclusionSet,
            ClassMemberLookup lookup,
            FlowObfuscationExclusions flowObfuscationExclusions,
            ClassInitOrderHandler classInitOrderHandler
    ) throws Exception, IOException {
        if (entry.hasNoField()) {
            return null;
        }

        String fieldName = entry.getFieldName();
        String internalName = entry.getInternalClassName();
        String newClassName = entry.getNewClassName();
        String descriptor = entry.getFieldDescriptor();

        // Previously chosen host for this class?
        if (hostClassByOldName.containsKey(internalName)) {
            ProgramClass host = (ProgramClass) hostClassByOldName.get(internalName);
            if (!hasExcludedMembersInClass(entry, host, fieldName, descriptor, lookup, nameExclusionSet)) {
                return host;
            }
        }

        if (changeLogMapping.isNewClassName(newClassName)
                && !changeLogMapping.getOriginalClassName(newClassName).equals(internalName)) {
            return null;
        }

        CountingBag candidates = this.findCandidateClasses(internalName, referenceCounts, changeLogMapping);
        if (candidates == null) {
            return null;
        }

        String packagePath = ClassFileBase.getPackagePath(internalName);

        for (Object c : candidates.getSortedByCount()) {
            ProgramClass candidate = (ProgramClass) c;
            String candidateName = candidate.getClassName();

            if (candidate.getPackagePath().equals(packagePath)
                    && !changeLogMapping.hasClassMapping(candidateName)
                    && !nameExclusionSet.isClassNameExcluded(candidateName)
                    && this.canHostPredicateField(candidate, flowObfuscationExclusions, classInitOrderHandler, lookup, false)
                    && !hasExcludedMembersInClass(entry, candidate, fieldName, descriptor, lookup, nameExclusionSet)
                    && !hostClassByOldName.containsValue(candidate)) {
                hostClassByOldName.put(internalName, candidate);
                return candidate;
            }
        }

        return null;
    }

    /** True if the field or any of its accessor methods already exists in {@code host} and is name-excluded. */
    private boolean hasExcludedMembersInClass(
            ChangeLogMemberEntry entry,
            ProgramClass host,
            String fieldName,
            String descriptor,
            ClassMemberLookup lookup,
            NameExclusionSet nameExclusionSet
    ) throws Exception, IOException {
        String hostName = host.getClassName();

        FieldInfo field = lookup.findField(hostName, fieldName, descriptor);

        MethodInfo setter = entry.getSetterMethodName() != null
                ? lookup.findDeclaredMethod(host, new MethodSignature(entry.getNewSetterMethodName(), OpaquePredicateField.setterDescriptorFor(descriptor)))
                : null;
        MethodInfo getter = entry.getGetterMethodName() != null
                ? lookup.findDeclaredMethod(host, new MethodSignature(entry.getNewGetterMethodName(), OpaquePredicateField.getterDescriptorFor(descriptor)))
                : null;
        MethodInfo altGetter = entry.getAltGetterMethodName() != null
                ? lookup.findDeclaredMethod(host, new MethodSignature(entry.getNewAltGetterMethodName(), OpaquePredicateField.getterDescriptorFor(descriptor)))
                : null;

        return (field != null && nameExclusionSet.isFieldExcluded(field))
                || (setter != null && nameExclusionSet.isMethodExcluded(setter))
                || (getter != null && nameExclusionSet.isMethodExcluded(getter))
                || (altGetter != null && nameExclusionSet.isMethodExcluded(altGetter));
    }

    public OpaquePredicateField resolveFieldForChangeLogEntry(
            ChangeLogMemberEntry entry,
            SetMultiMap classesByOldName,
            CountingBag referenceCounts,
            NameExclusionSet nameExclusionSet,
            Random rng,
            TwoKeyMap predicateFieldsByClass,
            Map classRenames,
            Map fieldRenames,
            TwoKeyMap excludedFields,
            Map addedFieldMappings,
            TwoKeyMap methodRenames,
            Map excludedMethods,
            TwoKeyMap addedMethodMappings,
            boolean isTraceBack,
            int packageCount,
            ClassMemberLookup lookup,
            Map hostClassByOldName,
            FlowObfuscationExclusions flowObfuscationExclusions,
            ClassInitOrderHandler classInitOrderHandler,
            InheritedMemberAnalyzer analyzer
    ) throws Exception, IOException {
        String internalName = entry.getInternalClassName();
        String dottedName = Utils.slashesToDots(internalName);
        String kind = entryKindLabel(isTraceBack);
        String classPrefix = "Class '" + dottedName + "' appears as a Flow Obfuscation " + kind;

        this.changeLogMapping.getFlowEntryFieldNames(internalName);

        if (!this.changeLogMapping.hasClassMapping(internalName) && !this.changeLogMapping.isRemovedClass(internalName)) {
            this.changeLogMapping.reportFatalError(classPrefix + " but does not appear in the main part of the change log. (C)");
            return null;
        }

        if (!entry.hasNoField() && !entry.hasIncompleteMapping()) {
            this.changeLogMapping.reportFatalError(classPrefix + " but its entry in the main part of the change log is corrupt.");
            return null;
        }

        ClassFileBase classFile = ClassHierarchyNode.findClassFile(internalName);

        // ---- Class still exists under its old name ----
        if (classFile != null) {
            ObservableHolder error = new ObservableHolder();

            if (entry.hasCustomReferenceType()) {
                FlowObfuscationGroup group = (FlowObfuscationGroup) this.groupsByClass.get(classFile);
                String elementClassName = entry.getArrayElementClassName();
                ClassFileBase elementClass = ClassHierarchyNode.findClassFile(elementClassName);
                if (elementClass == null || !group.isCommonClass(elementClass)) {
                    error.setValue(
                            "Type '" + Utils.slashesToDots(elementClassName) + "' appears in Flow Obfuscation " + kind
                                    + " '" + dottedName
                                    + "' but it is no longer available within the corresponding group. You must distribute this application as a whole.");
                }
            }

            if (!error.isValueNull()) {
                this.changeLogMapping.logError((String) error.getValue());
                return null;
            }

            if (this.isUsedInEarlierPass(entry, classFile, analyzer, error)) {
                this.changeLogMapping.logError((String) error.getValue());
                return null;
            }

            if (classFile.isInterface()) {
                this.changeLogMapping.logError(
                        classPrefix + " but it is now an interface. Another class had to be used.  You must distribute this application as a whole.");
                return null;
            }

            if (this.hasExcludedChangeLogMembers(entry, classFile, excludedFields, excludedMethods, nameExclusionSet, lookup, error)) {
                this.changeLogMapping.logError((String) error.getValue());
                return null;
            }

            if (!classFile.isPublic() && packageCount != 1) {
                this.changeLogMapping.logError(
                        classPrefix + " but it is no longer public. Another class had to be used. You must distribute this application as a whole.");
                return null;
            }

            return this.getOrCreateChangeLogField(
                    entry, classFile, this.changeLogMapping, rng, predicateFieldsByClass, fieldRenames, methodRenames, analyzer, lookup);
        }

        // ---- Class no longer exists: look for a library class, else find a new host ----
        ClassFileBase libraryClass = this.findLibraryClass(internalName, classesByOldName);
        if (libraryClass != null) {
            this.changeLogMapping.reportFatalError(
                    classPrefix + " but could not be found. However, it must be referenced by '"
                            + libraryClass.getDottedClassName() + "' which has not be opened.");
            return null;
        }

        ProgramClass host = this.findHostClassForChangeLogEntry(
                entry, referenceCounts, hostClassByOldName, this.changeLogMapping, nameExclusionSet, lookup,
                flowObfuscationExclusions, classInitOrderHandler);

        if (host == null) {
            this.changeLogMapping.logError(
                    classPrefix + " but is no longer available. Another class had to be used.  You must distribute this application as a whole.");
            return null;
        }

        classRenames.put(internalName, host.getClassName());
        String typeName = entry.getFieldTypeName();

        OpaquePredicateField result = this.getOrCreateChangeLogField(
                entry, host, this.changeLogMapping, rng, predicateFieldsByClass, fieldRenames, methodRenames, analyzer, lookup);

        addedFieldMappings.put(new Triple(host.getClassName(), result.getFieldName(), typeName), entry.getNewFieldName());

        if (entry.hasSetterMethod()) {
            String hostName = host.getClassName();

            if (result.hasSetter()) {
                AbstractMethodInfo setter = result.getSetter();
                addedMethodMappings.putValue(hostName, new Triple(setter.getSourceName(), typeName, "void"), entry.getNewSetterMethodName());
            }
            if (result.hasGetter()) {
                AbstractMethodInfo getter = result.getGetter();
                addedMethodMappings.putValue(hostName, new Triple(getter.getSourceName(), "", typeName), entry.getNewGetterMethodName());
            }
            if (result.hasNegatedGetter()) {
                AbstractMethodInfo negated = result.getNegatedGetter();
                addedMethodMappings.putValue(hostName, new Triple(negated.getSourceName(), "", typeName), entry.getNewAltGetterMethodName());
            }
        }

        return result;
    }

    public boolean restoreChangeLogFields(
            HashSet packageNames,
            CountingBag referenceCounts,
            NameExclusionSet nameExclusionSet,
            FlowObfuscationExclusions flowObfuscationExclusions,
            ClassInitOrderHandler classInitOrderHandler,
            Random rng,
            TwoKeyMap predicateFieldsByClass,
            SetMultiMap fieldSignaturesByClass,
            InheritedMemberAnalyzer analyzer,
            ClassMemberLookup lookup
    ) throws Exception, IOException {
        HashMap fieldsByEntry = Utils.createHashMap();
        HashMap hostClassByOldName = Utils.createHashMap();
        HashMap classRenames = Utils.createHashMap(7);
        HashMap fieldRenames = Utils.createHashMap(7);
        TwoKeyMap excludedFields = new TwoKeyMap(7, 7);
        HashMap addedFieldMappings = Utils.createHashMap(7);
        TwoKeyMap methodRenames = new TwoKeyMap();
        HashMap excludedMethods = Utils.createHashMap();
        TwoKeyMap addedMethodMappings = new TwoKeyMap();
        boolean success = true;

        SetMultiMap classesByOldName = new SetMultiMap();
        Map memberEntries = this.changeLogMapping.getMemberClassEntries();

        for (Object o : memberEntries.entrySet()) {
            Entry entry = (Entry) o;
            String dottedName = (String) entry.getKey();
            ClassFileBase classFile = ClassHierarchyNode.findClassFile(Utils.dotsToSlashes(dottedName));
            if (classFile != null && (!classFile.isInterface() || classFile.supportsJava8())) {
                ObjectPair pair = (ObjectPair) entry.getValue();
                ChangeLogMemberEntry first = (ChangeLogMemberEntry) pair.getFirst();
                ChangeLogMemberEntry second = (ChangeLogMemberEntry) pair.getSecond();
                classesByOldName.addValue(first.getInternalClassName(), classFile);
                classesByOldName.addValue(second.getInternalClassName(), classFile);
            }
        }

        // ---- Group fields (trace-back entries) ----
        Enumeration traceBackEntries = this.changeLogMapping.getSortedTraceBackEntries();
        while (traceBackEntries.hasMoreElements() && success) {
            ChangeLogMemberEntry entry = (ChangeLogMemberEntry) traceBackEntries.nextElement();
            OpaquePredicateField field = this.resolveFieldForChangeLogEntry(
                    entry, classesByOldName, referenceCounts, nameExclusionSet, rng, predicateFieldsByClass,
                    classRenames, fieldRenames, excludedFields, addedFieldMappings, methodRenames, excludedMethods,
                    addedMethodMappings, true, packageNames.size(), lookup, hostClassByOldName,
                    flowObfuscationExclusions, classInitOrderHandler, analyzer);

            if (field == null) {
                success = false;
                continue;
            }

            ClassFileBase owner = field.getOwnerClass();
            this.addFieldType((FlowObfuscationGroup) this.groupsByClass.get(owner), field.getFieldType());
            this.groupFields.add(field);
            fieldSignaturesByClass.addValue(owner, field.getFieldSignature());
            fieldsByEntry.put(entry, field);
        }

        // ---- Package fields (forward-class entries) ----
        ListMultimap forwardEntries = this.changeLogMapping.getSortedForwardClassEntries();
        Enumeration forwardKeys = forwardEntries.keys();
        while (forwardKeys.hasMoreElements() && success) {
            String dottedName = (String) forwardKeys.nextElement();
            String internalName = Utils.dotsToSlashes(dottedName);
            if (!packageNames.contains(internalName)) {
                continue;
            }

            for (Object e : forwardEntries.getValues(dottedName)) {
                ChangeLogMemberEntry entry = (ChangeLogMemberEntry) e;
                OpaquePredicateField field = this.resolveFieldForChangeLogEntry(
                        entry, classesByOldName, referenceCounts, nameExclusionSet, rng, predicateFieldsByClass,
                        classRenames, fieldRenames, excludedFields, addedFieldMappings, methodRenames, excludedMethods,
                        addedMethodMappings, false, packageNames.size(), lookup, hostClassByOldName,
                        flowObfuscationExclusions, classInitOrderHandler, analyzer);

                if (field == null) {
                    success = false;
                    continue;
                }

                this.packageFieldsByPackage.addValue(internalName, field);
                fieldsByEntry.put(entry, field);
                ClassFileBase owner = ClassHierarchyNode.findClassFile(field.getOwnerClassName());
                fieldSignaturesByClass.addValue(owner, field.getFieldSignature());
                this.addFieldType((FlowObfuscationGroup) this.groupsByClass.get(owner), field.getFieldType());
            }
        }

        // ---- Build per-class field pairs ----
        if (success) {
            for (Object o : memberEntries.entrySet()) {
                Entry entry = (Entry) o;
                String dottedName = (String) entry.getKey();
                ClassFileBase classFile = ClassHierarchyNode.findClassFile(Utils.dotsToSlashes(dottedName));
                if (classFile == null) {
                    continue;
                }

                if (classFile.isInterface() && !classFile.supportsJava8()) {
                    this.changeLogMapping.logMessage("Class '" + dottedName + "' has been changed to be an interface. No action required.");
                    continue;
                }

                ObjectPair pair = (ObjectPair) entry.getValue();
                OpaquePredicateField groupField = (OpaquePredicateField) fieldsByEntry.get(pair.getFirst());
                OpaquePredicateField packageField = (OpaquePredicateField) fieldsByEntry.get(pair.getSecond());

                if (groupField == null || packageField == null) {
                    success = false;
                    this.changeLogMapping.logError(
                            "Class '" + dottedName + "' affected by a change in class grouping (B). You must distribute this application as a whole.");
                } else if (this.isFieldClassInAllGroupings(classFile, groupField) && this.isFieldClassInAllGroupings(classFile, packageField)) {
                    this.fieldPairsByClass.put(classFile, new FlowFieldPair(groupField, packageField, classFile.getPackagePath()));
                } else {
                    success = false;
                    this.changeLogMapping.logError(
                            "Class '" + dottedName + "' affected by a change in class grouping (A). You must distribute this application as a whole.");
                }
            }

            if (!success) {
                this.fieldPairsByClass.clear();
            }
        }

        // ---- Apply collected renames to the change log ----
        for (Object o : classRenames.entrySet()) {
            Entry entry = (Entry) o;
            this.changeLogMapping.renameMappedClass((String) entry.getKey(), (String) entry.getValue());
        }

        for (Object o : fieldRenames.entrySet()) {
            Entry entry = (Entry) o;
            Triple key = (Triple) entry.getKey();
            this.changeLogMapping.renameRawFieldMapping((String) key.getFirst(), (String) key.getSecond(), (String) key.getThird(), (String) entry.getValue());
        }

        Enumeration excludedClassKeys = excludedFields.keys();
        while (excludedClassKeys.hasMoreElements()) {
            String className = (String) excludedClassKeys.nextElement();
            Map inner = excludedFields.getInnerMap(className);
            for (Object k : inner.keySet()) {
                ObjectPair pair = (ObjectPair) k;
                this.changeLogMapping.removeRawFieldMapping(className, (String) pair.getFirst(), (String) pair.getSecond());
            }
        }

        for (Object o : addedFieldMappings.entrySet()) {
            Entry entry = (Entry) o;
            Triple key = (Triple) entry.getKey();
            this.changeLogMapping.addRawFieldMapping((String) key.getFirst(), (String) key.getSecond(), (String) key.getThird(), (String) entry.getValue());
        }

        for (Object o : methodRenames.entrySet()) {
            Entry outer = (Entry) o;
            Map inner = (Map) outer.getValue();
            for (Object i : inner.entrySet()) {
                Entry innerEntry = (Entry) i;
                Triple key = (Triple) innerEntry.getKey();
                this.changeLogMapping.renameRawMethodMapping(
                        (String) outer.getKey(), (String) key.getFirst(), (String) key.getSecond(), (String) key.getThird(), (String) innerEntry.getValue());
            }
        }

        for (Object o : excludedMethods.entrySet()) {
            Entry entry = (Entry) o;
            Triple value = (Triple) entry.getValue();
            this.changeLogMapping.removeRawMethodMapping((String) entry.getKey(), (String) value.getFirst(), (String) value.getSecond(), (String) value.getThird());
        }

        for (Object o : addedMethodMappings.entrySet()) {
            Entry outer = (Entry) o;
            String className = (String) outer.getKey();
            Map inner = (Map) outer.getValue();
            for (Object i : inner.entrySet()) {
                Entry innerEntry = (Entry) i;
                Triple key = (Triple) innerEntry.getKey();
                this.changeLogMapping.addRawMethodMapping(
                        className, (String) key.getFirst(), (String) key.getSecond(), (String) key.getThird(), (String) innerEntry.getValue());
            }
        }

        return success;
    }
}
