-- Production hardening for the existing Business Brain AI schema.
-- Existing base tables: public.products, public.customers, public.sales.

begin;

revoke all privileges on table public.products, public.customers, public.sales from anon, public;
revoke all privileges on table public.products, public.customers, public.sales from authenticated;
grant select, insert, update, delete on table public.products, public.customers to authenticated;
grant select on table public.sales to authenticated;
revoke all privileges on all sequences in schema public from anon, public, authenticated;
grant usage, select on all sequences in schema public to authenticated;

drop policy if exists "Owner manages products" on public.products;
create policy "Owner manages products" on public.products for all to authenticated
using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));

drop policy if exists "Owner manages customers" on public.customers;
create policy "Owner manages customers" on public.customers for all to authenticated
using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));

drop policy if exists "Owner manages sales" on public.sales;
create policy "Owner manages sales" on public.sales for select to authenticated
using (owner_id = (select auth.uid()));

create index if not exists products_owner_id_idx on public.products(owner_id);
create index if not exists customers_owner_id_idx on public.customers(owner_id);
create index if not exists sales_owner_id_idx on public.sales(owner_id);
create index if not exists sales_product_id_idx on public.sales(product_id);
create index if not exists sales_customer_id_idx on public.sales(customer_id);
create index if not exists sales_owner_created_at_idx on public.sales(owner_id, created_at desc);

create or replace function public.record_sale(
  p_product_id bigint, p_quantity numeric, p_customer_id bigint default null
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_owner_id uuid := auth.uid();
  v_product public.products%rowtype;
  v_sale_id bigint;
begin
  if v_owner_id is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_product_id is null or p_quantity is null or p_quantity <= 0 then
    raise exception 'Product and a positive quantity are required' using errcode = '22023';
  end if;
  select * into v_product from public.products
   where id = p_product_id and owner_id = v_owner_id for update;
  if not found then
    raise exception 'Product not found for this account' using errcode = 'P0002';
  end if;
  if v_product.quantity < p_quantity then
    raise exception 'Insufficient stock' using errcode = '23514';
  end if;
  if p_customer_id is not null and not exists (
    select 1 from public.customers where id = p_customer_id and owner_id = v_owner_id
  ) then
    raise exception 'Customer not found for this account' using errcode = '23503';
  end if;
  update public.products set quantity = quantity - p_quantity
   where id = v_product.id and owner_id = v_owner_id;
  insert into public.sales(owner_id,product_id,customer_id,product_name,quantity,unit_price,total,cost_total,currency)
  values(v_owner_id,v_product.id,p_customer_id,v_product.name,p_quantity,v_product.price,
         p_quantity*v_product.price,p_quantity*v_product.cost,v_product.currency)
  returning id into v_sale_id;
  return v_sale_id;
end;
$function$;

revoke all on function public.record_sale(bigint,numeric,bigint) from public, anon;
grant execute on function public.record_sale(bigint,numeric,bigint) to authenticated;
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;

commit;
