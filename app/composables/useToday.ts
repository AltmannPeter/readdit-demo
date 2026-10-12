/** Today's date (UTC, YYYY-MM-DD), fixed per page load so SSR and client agree. */
export const useToday = () => useState<string>('today', () => todayISO())
