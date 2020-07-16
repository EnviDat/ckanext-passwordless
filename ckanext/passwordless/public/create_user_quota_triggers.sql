CREATE FUNCTION public.trg_new_user_quota_check()
    RETURNS trigger
    LANGUAGE 'plpgsql'
    COST 100
    VOLATILE NOT LEAKPROOF
AS $BODY$BEGIN
   IF NOT(select (count(*)<= 200)
from "user"
where "user"."created" BETWEEN NOW() - INTERVAL '24 HOURS' AND NOW()
) THEN
      RAISE EXCEPTION 'New user quota exceeded';
   END IF;
   RETURN NEW;
END
$BODY$;

CREATE TRIGGER trg_user_before_insert_check_new_user_quota
    BEFORE INSERT
    ON public."user"
    FOR EACH ROW
    EXECUTE PROCEDURE public.trg_new_user_quota_check();