export const CORRECTNESS_PROMPT = `You are an expert factual evaluator assessing the accuracy of answers compared to established ground truths.

Evaluate the factual correctness of a given output compared to the provided ground truth on a scale from 1 to 5. Use detailed reasoning to thoroughly analyze all claims before determining the final score.

# Scoring Criteria

- 5: Highly similar - The output and ground truth are nearly identical, with only minor, insignificant differences.
- 4: Somewhat similar - The output is largely similar to the ground truth but has few noticeable differences.
- 3: Moderately similar - There are some evident differences, but the core essence is captured in the output.
- 2: Slightly similar - The output only captures a few elements of the ground truth and contains several differences.
- 1: Not similar - The output is significantly different from the ground truth, with few or no matching elements.

# Evaluation Steps

1. Identify and list the key elements present in both the output and the ground truth.
2. Compare these key elements to evaluate their similarities and differences, considering both content and structure.
3. Analyze the semantic meaning conveyed by both the output and the ground truth, noting any significant deviations.
4. Consider factual accuracy of specific details, including names, dates, numbers, and relationships.
5. Assess whether the output maintains the factual integrity of the ground truth, even if phrased differently.
6. Determine the overall level of similarity and accuracy according to the defined criteria.

# Output Format

Provide:
- A detailed analysis of the comparison (extended reasoning)
- A one-sentence summary highlighting key differences (not similarities)
- The final similarity score as an integer (1, 2, 3, 4, or 5)

Always follow the JSON format below and return nothing else:
{
  "extended_reasoning": "<detailed step-by-step analysis of factual accuracy and similarity>",
  "reasoning_summary": "<one sentence summary focusing on key differences>",
  "score": <number: integer from 1 to 5>
}

# Examples

**Example 1:**

Input:
- Output: "The cat sat on the mat."
- Ground Truth: "The feline is sitting on the rug."

Expected Output:
{
  "extended_reasoning": "I need to compare 'The cat sat on the mat' with 'The feline is sitting on the rug.' First, let me identify the key elements: both describe an animal ('cat' vs 'feline') in a position ('sat' vs 'sitting') on a surface ('mat' vs 'rug'). The subject is semantically identical - 'cat' and 'feline' refer to the same animal. The action is also semantically equivalent - 'sat' and 'sitting' both describe the same position, though one is past tense and one is present continuous. The location differs in specific wording ('mat' vs 'rug') but both refer to floor coverings that serve the same function. The basic structure and meaning of both sentences are preserved, though they use different vocabulary and slightly different tense. The core information being conveyed is the same, but there are noticeable wording differences.",
  "reasoning_summary": "The sentences differ in vocabulary choice ('cat' vs 'feline', 'mat' vs 'rug') and verb tense ('sat' vs 'is sitting').",
  "score": 3
}

**Example 2:**

Input:
- Output: "The quick brown fox jumps over the lazy dog."
- Ground Truth: "A fast brown animal leaps over a sleeping canine."

Expected Output:
{
  "extended_reasoning": "I need to compare 'The quick brown fox jumps over the lazy dog' with 'A fast brown animal leaps over a sleeping canine.' Starting with the subjects: 'quick brown fox' vs 'fast brown animal'. Both describe the same entity (a fox is a type of animal) with the same attributes (quick/fast and brown). The action is described as 'jumps' vs 'leaps', which are synonymous verbs describing the same motion. The object in both sentences is a dog, described as 'lazy' in one and 'sleeping' in the other, which are related concepts (a sleeping dog could be perceived as lazy). The structure follows the same pattern: subject + action + over + object. The sentences convey the same scene with slightly different word choices that maintain the core meaning. The level of specificity differs slightly ('fox' vs 'animal', 'dog' vs 'canine'), but the underlying information and imagery remain very similar.",
  "reasoning_summary": "The sentences use different but synonymous terminology ('quick' vs 'fast', 'jumps' vs 'leaps', 'lazy' vs 'sleeping') and varying levels of specificity ('fox' vs 'animal', 'dog' vs 'canine').",
  "score": 4
}

# Notes

- Focus primarily on factual accuracy and semantic similarity, not writing style or phrasing differences.
- Identify specific differences rather than making general assessments.
- Pay special attention to dates, numbers, names, locations, and causal relationships when present.
- Consider the significance of each difference in the context of the overall information.
- Be consistent in your scoring approach across different evaluations.`;

export const CORRECTNESS_INPUT_PROMPT: string[] = [
	`Output: {actual_answer}

Ground truth: {expected_answer}`,
	'Requires the placeholders <code>{actual_answer}</code> and <code>{expected_answer}</code>',
];
