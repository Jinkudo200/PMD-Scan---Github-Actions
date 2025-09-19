/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */
package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTStatement;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

/**
 * HIGH priority
 * Detects JSON.deserialize*, JSON.deserializeUntyped, JSON.deserializeStrict usage where argument
 * originates from untrusted sources (RestContext.request, ApexPages params, HttpRequest.getBody())
 * and flags when deserialized variables flow into sensitive sinks without detected validation.
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

        // Detect deserialization and validation calls
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            if (isDeserializeCall(call)) {
                ASTStatement stmt = call.ancestors(ASTStatement.class).first();
                if (stmt != null) {
                    ASTVariableExpression left = stmt.firstChild(ASTVariableExpression.class);
                    if (left != null) {
                        deserializedVars.add(Helper.getFQVariableName(left));
                    } else {
                        if (isUntrustedArgument(call)) {
                            asCtx(data).addViolation(call);
                        }
                    }
                }
            }

            // Heuristic: calls with "validate" in the name count as validations
            if (call.getMethodName() != null && call.getMethodName().toLowerCase().contains("validate")) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    validatedVars.add(Helper.getFQVariableName(v));
                }
            }
        }

        // Find uses of deserialized variables in sensitive sinks
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
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
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();
        return "JSON".equals(def) && (m.startsWith("deserialize") || m.equals("deserializeUntyped") || m.equals("deserializeStrict"))
                || (call.getImage() != null && call.getImage().contains("JSON.deserialize"));
    }

    private boolean isUntrustedArgument(ASTMethodCallExpression call) {
        for (ASTMethodCallExpression inner : call.descendants(ASTMethodCallExpression.class)) {
            String def = inner.getDefiningType() == null ? "" : inner.getDefiningType();
            String m = inner.getMethodName() == null ? "" : inner.getMethodName();
            if ("RestContext".equals(def)) return true;
            if ("ApexPages".equals(def) && "currentPage".equals(m)) return true;
            if ("HttpRequest".equals(def) && (m.equals("getBody") || m.contains("getParameter"))) return true;
            if (m.contains("getParameters")) return true;
        }
        return false;
    }

    private boolean isSensitiveSink(ASTMethodCallExpression call) {
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();
        if ("Database".equals(def) && (m.equals("query") || m.equals("countQuery"))) return true;
        if ("System".equals(def) && m.equals("schedule")) return true;
        if ("HttpRequest".equals(def) && (m.equals("setBody") || m.equals("setEndpoint"))) return true;
        if (call.getImage() != null && (call.getImage().contains("Database.insert") || call.getImage().contains("Database.update"))) return true;
        return false;
    }
}
