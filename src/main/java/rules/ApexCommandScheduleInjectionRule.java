package rules;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RulePriority;

/**
 * Detects System.schedule(System.enqueueJob, etc.) where cron or job name
 * is constructed from untrusted/untainted variables (simple taint-tracking).
 *
 * Priority: HIGH
 */
public class ApexCommandScheduleInjectionRule extends AbstractApexRule {

    private static final String SCHEDULER_CLASS = "System";
    private static final String SCHEDULER_METHOD = "schedule";
    private static final String ENQUEUE_METHOD = "enqueueJob";
    private static final String EXECUTE_BATCH = "executeBatch";

    private static final String STRING_CLASS = "String";
    private static final String ESCAPE_SINGLE_QUOTES = "escapeSingleQuotes";
    private static final String STRING_JOIN = "join";

    // Variables considered safe because they were assigned a literal or sanitized
    private final Set<String> safeVariables = new HashSet<>();

    public ApexCommandScheduleInjectionRule() {
        setPriority(RulePriority.HIGH);
        setName("ApexCommandScheduleInjectionRule");
        setMessage("Possible schedule/command injection: cron/job name built from untrusted input.");
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

    private void markSafeIfLiteralOrEscaped(ApexNode<?> node) {
        // Find variable expression inside (if any)
        ASTVariableExpression var = node.firstChild(ASTVariableExpression.class);
        if (var == null) {
            return;
        }
        // If right-hand side contains a literal => safe
        ASTLiteralExpression lit = node.firstChild(ASTLiteralExpression.class);
        if (lit != null && (lit.isString() || lit.isBoolean() || lit.isInteger())) {
            safeVariables.add(Helper.getFQVariableName(var));
            return;
        }

        // If RHS contains a method call to a known sanitizer (String.escapeSingleQuotes or String.join) => safe
        for (ASTMethodCallExpression mc : node.descendants(ASTMethodCallExpression.class).toList()) {
            if (Helper.isMethodName(mc, STRING_CLASS, ESCAPE_SINGLE_QUOTES)
                    || Helper.isMethodName(mc, STRING_CLASS, STRING_JOIN)) {
                safeVariables.add(Helper.getFQVariableName(var));
                return;
            }
        }

        // If RHS is a binary expression formed only from literals -> safe
        ASTBinaryExpression bin = node.firstChild(ASTBinaryExpression.class);
        if (bin != null) {
            boolean allLiterals = bin.descendants(ASTLiteralExpression.class).toList().stream().allMatch(l -> l.isString() || l.isInteger() || l.isBoolean());
            if (allLiterals) {
                safeVariables.add(Helper.getFQVariableName(var));
            }
        }
    }

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        // Detect System.schedule(...)
        if (Helper.isMethodName(node, SCHEDULER_CLASS, SCHEDULER_METHOD)) {
            // System.schedule(jobName, cronExpression, schedulable)
            // We need to check the cronExpression argument (usually the 2nd parameter)
            ASTNodeArg arg = findArgByIndex(node, 1);
            if (arg != null) {
                if (arg.isLiteral()) {
                    // literal cron: consider safe (but might be suspicious if it comes from user input)
                    // do nothing
                } else if (arg.isVariable()) {
                    String fq = Helper.getFQVariableName(arg.getVariable());
                    if (!safeVariables.contains(fq)) {
                        // variable used as cron but not marked safe -> violation
                        asCtx(data).addViolation(arg.getVariable());
                    }
                } else {
                    // other expression (concatenation or methodcall). Try to find underlying variable(s)
                    for (ASTVariableExpression v : node.descendants(ASTVariableExpression.class).toList()) {
                        String fq = Helper.getFQVariableName(v);
                        if (!safeVariables.contains(fq)) {
                            asCtx(data).addViolation(v);
                        }
                    }
                }
            }
        }

        // Detect System.enqueueJob(...) and Database.executeBatch(...) with tainted arguments
        if (Helper.isMethodName(node, SCHEDULER_CLASS, ENQUEUE_METHOD)
                || Helper.isMethodName(node, "System", "enqueueJob")
                || Helper.isMethodName(node, "Database", EXECUTE_BATCH)
                || node.getFullMethodName() != null && node.getFullMethodName().endsWith(".enqueueJob")) {
            // Enqueue usually takes a job object; we look for variable constructors with tainted args
            for (ASTVariableExpression v : node.descendants(ASTVariableExpression.class).toList()) {
                String fq = Helper.getFQVariableName(v);
                if (!safeVariables.contains(fq)) {
                    asCtx(data).addViolation(v);
                }
            }
        }

        return super.visit(node, data);
    }

    /**
     * Helper object to capture argument kinds.
     */
    private static final class ASTNodeArg {
        private final ASTLiteralExpression literal;
        private final ASTVariableExpression variable;

        ASTNodeArg(ASTLiteralExpression lit, ASTVariableExpression var) {
            this.literal = lit;
            this.variable = var;
        }

        boolean isLiteral() { return literal != null; }
        boolean isVariable() { return variable != null; }
        ASTLiteralExpression getLiteral() { return literal; }
        ASTVariableExpression getVariable() { return variable; }
    }

    /**
     * Try to find the N-th argument for a method call. This inspects child nodes and
     * counts expressions (literal, variable, binary, methodcall).
     * Returns null if not found.
     */
    private ASTNodeArg findArgByIndex(ASTMethodCallExpression call, int argIndex) {
        int count = 0;
        for (int i = 0; i < call.getNumChildren(); i++) {
            Object ch = call.getChild(i);
            if (ch instanceof ASTLiteralExpression) {
                if (count == argIndex) {
                    return new ASTNodeArg((ASTLiteralExpression) ch, null);
                }
                count++;
            } else if (ch instanceof ASTVariableExpression) {
                if (count == argIndex) {
                    return new ASTNodeArg(null, (ASTVariableExpression) ch);
                }
                count++;
            } else if (ch instanceof ASTBinaryExpression || ch instanceof ASTMethodCallExpression) {
                // treat complex expression as one argument
                if (count == argIndex) {
                    // try to extract any variable inside this expression
                    ASTVariableExpression v = ((ApexNode<?>) ch).descendants(ASTVariableExpression.class).first();
                    ASTLiteralExpression l = ((ApexNode<?>) ch).descendants(ASTLiteralExpression.class).first();
                    return new ASTNodeArg(l, v);
                }
                count++;
            }
            // else skip non-argument children
        }
        return null;
    }
}
