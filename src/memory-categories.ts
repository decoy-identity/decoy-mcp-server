/**
 * The memory categories: mem0's default categories plus finance, goals and relationships. The
 * same list the Decoy API accepts in a memory grant's `datatypes`, so a category also decides
 * which connections read a memory.
 */
export const MEMORY_CATEGORIES = [
  'personal_details', 'family', 'relationships', 'professional_details', 'finance', 'goals', 'sports', 'travel', 'food',
  'music', 'health', 'technology', 'hobbies', 'fashion', 'entertainment', 'milestones', 'user_preferences', 'misc',
] as const;
export type MemoryCategory = typeof MEMORY_CATEGORIES[number];

/** Where the categories that sit close together part, for whoever tags a memory (agent or model). */
export const CATEGORY_GUIDE =
  'finance: their own money (pay, savings, debts, investments, insurance, taxes, big costs); a work budget is professional_details. ' +
  'goals: what they are working towards; also give the goal\'s subject (saving for a home: goals and finance). ' +
  'relationships: friends and other people close to them outside their family; family: relatives, partner and pets.';
