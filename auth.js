const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function verifyUser(token) {
    try {
        if (!token) return { error: 'No token' };
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError || !user) return { error: 'Invalid Session' };

        // Fetch Role from DB (Player, Moderator, Admin)
        const { data: profile } = await supabase
            .from('profiles')
            .select('role')
            .eq('id', user.id)
            .single();

        return { user: { ...user, role: profile?.role || 'player' }, error: null };
    } catch (err) { return { error: 'Internal Auth Error' }; }
}

module.exports = { verifyUser };
