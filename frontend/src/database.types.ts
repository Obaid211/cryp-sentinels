// ECDAT — database type placeholders. The repo has no strict DB schema,
// so we declare the minimum required by the Supabase generic to keep
// `verbatimModuleSyntax` clean. Extend as your DB grows.
export type Database = {
  // Core tables will be added here. Example placeholder:
  // public: {
  //   users: { id: string; email: string; created_at: string }
  // }
}
