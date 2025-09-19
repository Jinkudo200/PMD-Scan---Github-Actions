package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
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
    public Object visit(ASTVariableDeclaration node, Object data) {
        markSafeIfLiteralOrEscaped(node);
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTAssignmentExpression node, Object data) {
        markSafeIfLiteralOrEscaped(node);
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTFieldDeclaration node, Object data) {
        markSafeIfLiteralOrEscaped(node);
        return super.visit(node, data);
    }

    private void markSafeIfLiteralOrEscaped(Object nodeObj) {
        ASTVariableExpression var = null;
        ASTLiteralExpression literal = null;
        ASTMethodCallExpression methodCall = null;

        if (nodeObj instanceof ASTVariableDeclaration) {
            ASTVariableDeclaration node = (ASTVariableDeclaration) nodeObj;
            var = node.firstChild(ASTVariableExpression.class);
            literal = node.firstChild(ASTLiteralExpression.class);
            methodCall = node.firstChild(ASTMethodCallExpression.class);
        } else if (nodeObj instanceof ASTAssignmentExpression) {
            ASTAssignmentExpression node = (ASTAssignmentExpression) nodeObj;
            var = node.firstChild(ASTVariableExpression.class);
            literal = node.firstChild(ASTLiteralExpression.class);
            methodCall = node.firstChild(ASTMethodCallExpression.class);
        } else if (nodeObj instanceof ASTFieldDeclaration) {
            ASTFieldDeclaration node = (ASTFieldDeclaration) nodeObj;
            var = node.firstChild(ASTVariableExpression.class);
            literal = node.firstChild(ASTLiteralExpression.class);
            methodCall = node.firstChild(ASTMethodCallExpression.class);
        }

        if (var != null) {
            if (literal != null && (literal.isString() || literal.isBoolean() || literal.isInteger())) {
                safeVariables.add(Helper.getFQVariableName(var));
            }
            if (methodCall != null && (Helper.isMethodName(methodCall, ESCAPE_SINGLE_QUOTES)
                    || Helper.isMethodName(methodCall, STRING_JOIN))) {
                safeVariables.add(Helper.getFQVariableName(var));
            }
        }
    }

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        if (!Helper.isMethodName(node, SYSTEM_SCHEDULER)) {
            return super.visit(node, data);
        }

        ASTVariableExpression var = node.firstChild(ASTVariableExpression.class);
        ASTLiteralExpression literal = node.firstChild(ASTLiteralExpression.class);

        if (literal != null) {
            // literal is safe
        } else if (var != null) {
            if (!safeVariables.contains(Helper.getFQVariableName(var))) {
                asCtx(data).addViolation(var);
            }
        }

        return super.visit(node, data);
    }
}
