
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { useToast } from "@/components/ui/use-toast";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";

type Props = {
  onSubmitted?: () => void;
};

export default function DeclarationForm({ onSubmitted }: Props) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: profile } = useCurrentProfile();

  const [classeId, setClasseId] = useState<string>("");
  const [declaredAt, setDeclaredAt] = useState<string>(new Date().toISOString().slice(0, 10));
  const [inscrits, setInscrits] = useState<string>("0");
  const [rates, setRates] = useState<string>("0");
  const [commentaire, setCommentaire] = useState<string>("");

  const { data: classes, isLoading: classesLoading } = useQuery({
    queryKey: ["classes-active"],
    queryFn: async () => {
  // TODO: Remplacer par appel API Express ou mock
        .from("classes")
        .select("id, nom_classe, is_active")
        .eq("is_active", true)
        .order("nom_classe", { ascending: true });
      if (error) throw error;
      return data || [];
    },
  });

  const mutation = useMutation({
    mutationFn: async () => {
      if (!profile?.id) throw new Error("Profil introuvable");
      if (!classeId) throw new Error("Veuillez sélectionner une session (classe)");
      const payload = {
        profile_id: profile.id,
        classe_id: classeId,
        declared_at: declaredAt,
        inscriptions_count: Number(inscrits) || 0,
        inscriptions_ratees_count: Number(rates) || 0,
        commentaire: commentaire || null,
        segment_id: "00000000-0000-0000-0000-000000000000", // Default segment
        ville_id: "00000000-0000-0000-0000-000000000000", // Default ville
      };
  // TODO: Remplacer par appel API Express ou mock
      if (error) throw error;
    },
    onSuccess: () => {
      toast({
        title: "Déclaration enregistrée",
        description: "Votre activité commerciale a été déclarée avec succès.",
      });
      // Rafraîchir les listes/agrégats
      queryClient.invalidateQueries({ queryKey: ["declarations_inscriptions"] });
      if (onSubmitted) onSubmitted();
      // Reset rapide
      setClasseId("");
      setInscrits("0");
      setRates("0");
      setCommentaire("");
      setDeclaredAt(new Date().toISOString().slice(0, 10));
    },
    onError: (err: any) => {
      toast({
        title: "Erreur",
        description: err?.message || "Impossible d'enregistrer la déclaration",
        variant: "destructive",
      });
    },
  });

  return (
    <div className="space-y-4">
      <div>
        <Label>Session (classe)</Label>
        <Select value={classeId} onValueChange={setClasseId}>
          <SelectTrigger className="w-full">
            <SelectValue placeholder={classesLoading ? "Chargement..." : "Sélectionner une session"} />
          </SelectTrigger>
          <SelectContent>
            {(classes || []).map((c: any) => (
              <SelectItem key={c.id} value={c.id}>
                {c.nom_classe}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div>
          <Label>Date de l'activité</Label>
          <Input type="date" value={declaredAt} onChange={(e) => setDeclaredAt(e.target.value)} />
        </div>
        <div>
          <Label>Inscrits</Label>
          <Input type="number" min={0} value={inscrits} onChange={(e) => setInscrits(e.target.value)} />
        </div>
        <div>
          <Label>Inscrits ratés</Label>
          <Input type="number" min={0} value={rates} onChange={(e) => setRates(e.target.value)} />
        </div>
      </div>

      <div>
        <Label>Commentaire</Label>
        <Input value={commentaire} onChange={(e) => setCommentaire(e.target.value)} placeholder="Optionnel" />
      </div>

      <div className="flex justify-end">
        <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
          {mutation.isPending ? "Enregistrement..." : "Enregistrer"}
        </Button>
      </div>
    </div>
  );
}
