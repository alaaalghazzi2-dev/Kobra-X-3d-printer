import { createClient } from 'npm:@supabase/supabase-js@2.95.3';

const cors = { 'Access-Control-Allow-Origin': 'https://alaaalghazzi2-dev.github.io', 'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Vary': 'Origin' };
const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
const perms = ['dashboard','products','inventory','customers','orders','finance','reports','invoices','reminders','settings'];

Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return reply({ error: 'Method not allowed' }, 405);
  const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
  try {
    const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
    if (!token) return reply({ error: 'يلزم تسجيل الدخول' }, 401);
    const { data: identity, error: authError } = await admin.auth.getUser(token);
    if (authError || !identity.user) return reply({ error: 'جلسة الدخول غير صالحة' }, 401);
    const { data: caller, error: callerError } = await admin.from('profiles').select('role').eq('user_id', identity.user.id).single();
    if (callerError || caller?.role !== 'admin') return reply({ error: 'إدارة المستخدمين متاحة للمدير فقط' }, 403);
    const body = await req.json();
    if (body.action === 'list') {
      const { data, error } = await admin.from('profiles').select('user_id,name,role,permissions').order('name');
      if (error) throw error;
      const users = await Promise.all((data || []).map(async profile => {
        const { data: auth, error } = await admin.auth.admin.getUserById(profile.user_id);
        if (error) throw error;
        return { ...profile, email: auth.user.email };
      }));
      return reply({ users });
    }
    if (!['create','update'].includes(body.action)) return reply({ error: 'عملية غير معروفة' }, 400);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const role = body.role;
    if (!name || name.length > 100 || !['admin','staff'].includes(role)) return reply({ error: 'تحقق من الاسم والدور' }, 400);
    if (!Array.isArray(body.permissions) || body.permissions.some((p: unknown) => typeof p !== 'string' || !perms.includes(p))) return reply({ error: 'صلاحيات غير صالحة' }, 400);
    const permissions = role === 'admin' ? ['all'] : [...new Set(body.permissions)];
    const password = body.password;
    if (password !== undefined && (typeof password !== 'string' || password.length < 10 || password.length > 72)) return reply({ error: 'كلمة المرور من 10 إلى 72 حرفاً' }, 400);
    if (body.action === 'create') {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password) return reply({ error: 'أدخل بريداً صحيحاً وكلمة مرور' }, 400);
      const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      if (error) return reply({ error: error.message }, 400);
      const { error: profileError } = await admin.from('profiles').insert({ user_id: data.user.id, name, role, permissions });
      if (profileError) {
        await admin.auth.admin.deleteUser(data.user.id);
        throw profileError;
      }
      return reply({ success: true });
    }
    if (typeof body.user_id !== 'string') return reply({ error: 'معرّف الحساب مطلوب' }, 400);
    // Prevent locking out the administrator performing this action.
    if (body.user_id === identity.user.id && role !== 'admin') return reply({ error: 'لا يمكنك إزالة صلاحية المدير من حسابك الحالي' }, 400);
    const { data: target, error: targetError } = await admin.from('profiles').select('user_id').eq('user_id', body.user_id).maybeSingle();
    if (targetError) throw targetError;
    if (!target) return reply({ error: 'الحساب غير موجود' }, 404);
    if (password) {
      const { error } = await admin.auth.admin.updateUserById(body.user_id, { password });
      if (error) return reply({ error: error.message }, 400);
    }
    const { error } = await admin.from('profiles').update({ name, role, permissions }).eq('user_id', body.user_id);
    if (error) throw error;
    return reply({ success: true });
  } catch (error) {
    console.error(error);
    return reply({ error: 'تعذّر تنفيذ العملية. حاول مجدداً.' }, 500);
  }
});
