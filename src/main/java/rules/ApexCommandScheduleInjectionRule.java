package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

public class ApexCommandScheduleInjectionRule extends AbstractApexRule {

    private static final String SYSTEM_SCHEDULER = "System.schedule";
    private static final String STRING_JOIN = "String.join";
    private static final String ESCAPE_SINGLE_QUOTES = "String.escapeSingleQuotes";

    private final Set<String> safeVariables = new HashSet<>();

    public ApexCommandScheduleInjectionRule() {
        setPriority(RulePriority.HIGH);
    }

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {

        // Check for System.schedule calls
        if (Helper.isMethodName(node, SYSTEM_SCHEDULER)) {
            ASTVariableExpression var = node.firstChild(ASTVariableExpression.class);
            ASTBinaryExpression binExpr = node.firstChild(ASTBinaryExpression.class);
            ASTLiteralExpression literal = node.firstChild(ASTLiteralExpression.class);

            // If literal string, consider safe
            if (literal != null) {
                // Do nothing, safe
            } else if (var != null) {
                String fqName = Helper.getFQVariableName(var);
                if (!safeVariables.contains(fqName)) {
                    asCtx(data).addViolation(var);
                }
            } else if (binExpr != null) {
                checkBinaryExpression(binExpr, data);
            }
        }

        return super.visit(node, data);
    }

    private void checkBinaryExpression(ASTBinaryExpression node, Object data) {
        ASTVariableExpression var = node.firstChild(ASTVariableExpression.class);
        ASTMethodCallExpression methodCall = node.firstChild(ASTMethodCallExpression.class);
        ASTLiteralExpression literal = node.firstChild(ASTLiteralExpression.class);

        boolean isSafe = false;

        if (var != null && safeVariables.contains(Helper.getFQVariableName(var))) {
            isSafe = true;
        }

        if (methodCall != null) {
            if (Helper.isMethodName(methodCall, ESCAPE_SINGLE_QUOTES) || Helper.isMethodName(methodCall, STRING_JOIN)) {
                isSafe = true;
            }
        }

        if (literal != null) {
            isSafe = true; // literals are safe
        }

        if (!isSafe) {
            asCtx(data).addViolation(node);
        }

        // Recurse into left/right children
        ASTBinaryExpression left = node.firstChild(ASTBinaryExpression.class);
        if (left != null) checkBinaryExpression(left, data);
    }

    @Override
    public Object visit(ApexNode<?> node, Object data) {
        // Collect safe variables: literals, numbers, booleans, or escaped strings
        ASTVariableExpression var = node.firstChild(ASTVariableExpression.class);
        ASTLiteralExpression literal = node.firstChild(ASTLiteralExpression.class);
        ASTMethodCallExpression methodCall = node.firstChild(ASTMethodCallExpression.class);

        if (var != null && literal != null) {
            if (literal.isString() || literal.isInteger() || literal.isBoolean()) {
                safeVariables.add(Helper.getFQVariableName(var));
            }
        }

        if (methodCall != null && Helper.isMethodName(methodCall, ESCAPE_SINGLE_QUOTES)) {
            if (var != null) safeVariables.add(Helper.getFQVariableName(var));
        }

        return super.visit(node, data);
    }
}
