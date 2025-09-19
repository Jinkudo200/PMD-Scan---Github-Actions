package rules;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTStatement;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

/**
 * Detect JSON.deserialize* calls with untrusted input and flag propagation into sensitive sinks.
 *
 * Priority: HIGH
 */
public class ApexInsecureDeserializationRule extends AbstractApexRule {

    private final Set<String> deserializedVars = new HashSet<>();
    private final Set<String> validatedVars = new HashSet<>();

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        // 1) Detect deserialization and collect the target variable (if assigned)
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class).toList()) {
            if (isDeserializeCall(call)) {
                // Try to find a surrounding variable declaration or assignment that stores the result
                ASTVariableDeclaration varDecl = call.ancestors(ASTVariableDeclaration.class).first();
                if (varDecl != null) {
                    ASTVariableExpression v = varDecl.firstChild(ASTVariableExpression.class);
                    if (v != null) {
                        deserializedVars.add(Helper.getFQVariableName(v));
                    } else {
                        // no variable expression - still flag the call if its argument is untrusted
                        if (isUntrustedArgument(call)) {
                            asCtx(data).addViolation(call);
                        }
                    }
                } else {
                    // assignment: left side of assignment
                    ASTAssignmentExpression assign = call.ancestors(ASTAssignmentExpression.class).first();
                    if (assign != null) {
                        ASTVariableExpression left = assign.firstChild(ASTVariableExpression.class);
                        if (left != null) {
                            deserializedVars.add(Helper.getFQVariableName(left));
                        } else if (isUntrustedArgument(call)) {
                            asCtx(data).addViolation(call);
                        }
                    } else {
                        // not stored - if argument is untrusted, flag
                        if (isUntrustedArgument(call)) {
                            asCtx(data).addViolation(call);
                        }
                    }
                }
            }

            // Heuristic validations (any call with "validate" in name marks its args as validated)
            String mname = call.getMethodName();
            if (mname != null && mname.toLowerCase().contains("validate")) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class).toList()) {
                    validatedVars.add(Helper.getFQVariableName(v));
                }
            }
        }

        // 2) If a deserialized variable (and not validated) flows into a sensitive sink, flag it
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class).toList()) {
            for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class).toList()) {
                String fq = Helper.getFQVariableName(v);
                if (deserializedVars.contains(fq) && !validatedVars.contains(fq) && isSensitiveSink(call)) {
                    asCtx(data).addViolation(v);
                }
            }
        }

        deserializedVars.clear();
        validatedVars.clear();
        return data;
    }

    private boolean isDeserializeCall(ASTMethodCallExpression call) {
        // Match JSON.deserialize, JSON.deserializeUntyped, JSON.deserializeStrict
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();
        if ("JSON".equals(def) && (m.startsWith("deserialize") || m.equals("deserializeUntyped") || m.equals("deserializeStrict"))) {
            return true;
        }
        // fallback: check full image for "JSON.deserialize"
        if (call.getImage() != null && call.getImage().contains("JSON.deserialize")) {
            return true;
        }
        return false;
    }

    private boolean isUntrustedArgument(ASTMethodCallExpression call) {
        // If any descendant reference expression or method call references RestContext, ApexPages.currentPage, HttpRequest.getBody, request params
        // we inspect method-call descendants and reference expressions
        for (ASTMethodCallExpression inner : call.descendants(ASTMethodCallExpression.class).toList()) {
            String def = inner.getDefiningType() == null ? "" : inner.getDefiningType();
            String m = inner.getMethodName() == null ? "" : inner.getMethodName();

            if ("RestContext".equals(def)) {
                return true;
            }
            if ("ApexPages".equals(def) && "currentPage".equals(m)) {
                return true;
            }
            if ("HttpRequest".equals(def) && (m.equals("getBody") || m.contains("getParameter"))) {
                return true;
            }

            // If method name contains getParameters/getParameter -> probably untrusted
            if (m.contains("getParameters") || m.contains("getParameter")) {
                return true;
            }
        }

        // Also inspect descendant variable expressions or reference expressions that may be direct references to RestContext.request
        for (net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression v : call.descendants(net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression.class).toList()) {
            String img = v.getImage();
            if (img != null && (img.equalsIgnoreCase("RestContext") || img.equalsIgnoreCase("request") || img.equalsIgnoreCase("params"))) {
                return true;
            }
        }
        return false;
    }

    private boolean isSensitiveSink(ASTMethodCallExpression call) {
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();

        if ("Database".equals(def) && (m.equalsIgnoreCase("query") || m.equalsIgnoreCase("countQuery") || m.equalsIgnoreCase("insert") || m.equalsIgnoreCase("update"))) {
            return true;
        }
        if ("System".equals(def) && m.equalsIgnoreCase("schedule")) {
            return true;
        }
        if ("HttpRequest".equals(def) && (m.equalsIgnoreCase("setBody") || m.equalsIgnoreCase("setEndpoint") || m.equalsIgnoreCase("setHeader"))) {
            return true;
        }
        if (call.getImage() != null && (call.getImage().contains("Database.insert") || call.getImage().contains("Database.update"))) {
            return true;
        }
        return false;
    }
}
