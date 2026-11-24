-- ADP-Rehearsal only. Captured before QC-002 on 2026-11-24.
CREATE OR REPLACE FUNCTION public.is_administrator() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'public' AS $function$ select exists(select 1 from public.administrator_roles where discord_id=public.current_discord_id()) $function$;
ALTER FUNCTION public.is_administrator() OWNER TO postgres;
GRANT EXECUTE ON FUNCTION public.is_administrator() TO PUBLIC, anon, authenticated, service_role;
