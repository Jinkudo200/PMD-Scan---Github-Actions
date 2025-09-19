package rules;

import net.sourceforge.pmd.lang.apex.ast.*;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

import java.util.HashSet;
import java.util.Set;

/**
 * Detects potential SOQL injection vulnerabilities in Apex code.
 */
public class ApexTaintSoqlRule extends AbstractApexRule {

    private final Set<String> safeVariables = new HashSet<>();

    public ApexTaintSoqlRule() {
        setRuleTargetSelector(RuleTargetSelector.forTypes(ASTUserClass.class));
        setPriority(RulePriority.HIGH); // PMD 7 style
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        // Track safe variables from method parameters
        for (ASTMethod m : node.descendants(ASTMethod.class)) {
            findSafeVariablesInMethodParams(m);
        }

        // Track variable declarations and assignments
        for (ASTVariableDeclaration vd : node.descendants(ASTVariableDeclaration.class)) {
            trackSafeVariable(vd);
        }
        for (ASTAssignmentExpression ae : node.descendants(ASTAssignmentExpression.class)) {
            trackSafeVariable(ae);
        }

        // Check Database.query / countQuery method calls
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            if (isQueryCall(call)) {
                checkUnsafeVariables(call, data);
            }
        }

        safeVariables.clear();
        return data;
    }

    private void findSafeVariablesInMethodParams(ASTMethod method) {
        for (ASTParameter param : method.children(ASTParameter.class)) {
            String typeName = param.getType();
            if (isSafeType(typeName)) {
                safeVariables.add(Helper.getFQVariableName(param));
            }
        }
    }

    private void trackSafeVariable(ApexNode<?> node) {
        ASTVariableExpression left = node.firstChild(ASTVariableExpression.class);
        ASTLiteralExpression literal = node.firstChild(ASTLiteralExpression.class);
        ASTMethodCallExpression rightCall = node.firstChild(ASTMethodCallExpression.class);

        if (left != null && literal != null) {
            if (literal.isInteger() || literal.isBoolean() || literal.isDouble()) {
                safeVariables.add(Helper.getFQVariableName(left));
            } else if (literal.isString()) {
                safeVariables.add(Helper.getFQVariableName(left));
            }
        }

        if (left != null && rightCall != null) {
            if (Helper.isMethodName(rightCall, "String", "escapeSingleQuotes")) {
                safeVariables.add(Helper.getFQVariableName(left));
            }
        }
    }

    private boolean isQueryCall(ASTMethodCallExpression call) {
        return Helper.isMethodName(call, "Database", "query")
                || Helper.isMethodName(call, "Database", "countQuery");
    }

    private void checkUnsafeVariables(ASTMethodCallExpression call, Object data) {
        for (ASTVariableExpression var : call.descendants(ASTVariableExpression.class)) {
            String fqName = Helper.getFQVariableName(var);
            if (!safeVariables.contains(fqName)) {
                asCtx(data).addViolation(var);
            }
        }
    }

    private boolean isSafeType(String typeName) {
        if (typeName == null) return false;
        switch (typeName.toLowerCase()) {
            case "double":
            case "long":
            case "decimal":
            case "boolean":
            case "id":
            case "integer":
            case "sobjecttype":
            case "schema.sobjecttype":
            case "sobjectfield":
            case "schema.sobjectfield":
                return true;
            default:
                return false;
        }
    }
}
