import { useState, useRef, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { 
  Send, 
  Search, 
  Phone, 
  Video, 
  MoreHorizontal,
  Users,
  Plus,
  Paperclip,
  Smile,
  Circle
} from "lucide-react";

interface User {
  id: string;
  nom: string;
  prenom: string;
  poste: string;
  avatar?: string;
  statut: "en_ligne" | "absent" | "occupe" | "hors_ligne";
  derniere_connexion?: Date;
}

interface Message {
  id: string;
  contenu: string;
  expediteur_id: string;
  conversation_id: string;
  date_envoi: Date;
  lu: boolean;
}

interface Conversation {
  id: string;
  nom?: string;
  type: "prive" | "groupe";
  participants: string[];
  dernier_message?: Message;
  messages_non_lus: number;
}

export function CommunicationInterne() {
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [messageText, setMessageText] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Mock data
  const utilisateurs: User[] = [
    {
      id: "1",
      nom: "Martin",
      prenom: "Marie",
      poste: "Responsable RH",
      statut: "en_ligne"
    },
    {
      id: "2",
      nom: "Dupont",
      prenom: "Jean",
      poste: "Commercial",
      statut: "occupe"
    },
    {
      id: "3",
      nom: "Leroy",
      prenom: "Sophie",
      poste: "Formatrice",
      statut: "en_ligne"
    },
    {
      id: "4",
      nom: "Bernard",
      prenom: "Pierre",
      poste: "Responsable Formation",
      statut: "absent"
    },
    {
      id: "5",
      nom: "Rousseau",
      prenom: "Amélie",
      poste: "Assistante",
      statut: "hors_ligne",
      derniere_connexion: new Date("2024-01-25T17:30:00")
    }
  ];

  const conversations: Conversation[] = [
    {
      id: "1",
      type: "prive",
      participants: ["current_user", "1"],
      messages_non_lus: 2
    },
    {
      id: "2", 
      type: "prive",
      participants: ["current_user", "2"],
      messages_non_lus: 0
    },
    {
      id: "3",
      nom: "Équipe Formation",
      type: "groupe",
      participants: ["current_user", "1", "3", "4"],
      messages_non_lus: 5
    },
    {
      id: "4",
      nom: "Direction",
      type: "groupe", 
      participants: ["current_user", "1", "2"],
      messages_non_lus: 1
    }
  ];

  const messages: Message[] = [
    {
      id: "1",
      contenu: "Bonjour, pouvez-vous me confirmer les horaires de la formation de demain ?",
      expediteur_id: "1",
      conversation_id: "1",
      date_envoi: new Date("2024-01-25T14:30:00"),
      lu: true
    },
    {
      id: "2",
      contenu: "Bien sûr ! La formation commence à 9h00 en salle B12",
      expediteur_id: "current_user", 
      conversation_id: "1",
      date_envoi: new Date("2024-01-25T14:32:00"),
      lu: true
    },
    {
      id: "3",
      contenu: "Parfait, merci beaucoup !",
      expediteur_id: "1",
      conversation_id: "1", 
      date_envoi: new Date("2024-01-25T14:33:00"),
      lu: false
    },
    {
      id: "4",
      contenu: "Y aura-t-il des supports à imprimer ?",
      expediteur_id: "1",
      conversation_id: "1",
      date_envoi: new Date("2024-01-25T14:35:00"),
      lu: false
    }
  ];

  const getUser = (id: string) => {
    if (id === "current_user") return { id: "current_user", nom: "Vous", prenom: "", poste: "", statut: "en_ligne" as const };
    return utilisateurs.find(u => u.id === id);
  };

  const getConversationName = (conversation: Conversation) => {
    if (conversation.nom) return conversation.nom;
    const otherUser = conversation.participants.find(id => id !== "current_user");
    const user = getUser(otherUser || "");
    return user ? `${user.prenom} ${user.nom}` : "Conversation";
  };

  const getConversationMessages = (conversationId: string) => {
    return messages.filter(m => m.conversation_id === conversationId);
  };

  const getStatusColor = (statut: string) => {
    switch (statut) {
      case "en_ligne": return "bg-green-500";
      case "occupe": return "bg-red-500";
      case "absent": return "bg-yellow-500";
      case "hors_ligne": return "bg-gray-400";
      default: return "bg-gray-400";
    }
  };

  const getStatusLabel = (statut: string) => {
    switch (statut) {
      case "en_ligne": return "En ligne";
      case "occupe": return "Occupé";
      case "absent": return "Absent";
      case "hors_ligne": return "Hors ligne";
      default: return statut;
    }
  };

  const sendMessage = () => {
    if (!messageText.trim() || !selectedConversation) return;
    
    // Ici on enverrait le message
    console.log("Envoi message:", messageText, "vers conversation:", selectedConversation);
    setMessageText("");
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [selectedConversation]);

  const filteredUsers = utilisateurs.filter(user => 
    `${user.prenom} ${user.nom}`.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const selectedConversationData = conversations.find(c => c.id === selectedConversation);
  const conversationMessages = selectedConversation ? getConversationMessages(selectedConversation) : [];

  return (
    <div className="h-[600px] flex border rounded-lg overflow-hidden">
      {/* Sidebar gauche */}
      <div className="w-80 border-r bg-muted/20">
        {/* Header sidebar */}
        <div className="p-4 border-b">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold">Messages</h3>
            <Button size="sm" variant="ghost">
              <Plus className="h-4 w-4" />
            </Button>
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Rechercher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>

        {/* Liste des conversations */}
        <ScrollArea className="flex-1">
          <div className="p-2">
            <div className="mb-4">
              <p className="text-sm font-medium text-muted-foreground mb-2 px-2">Conversations</p>
              {conversations.map((conversation) => (
                <div
                  key={conversation.id}
                  className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer hover:bg-muted/50 ${
                    selectedConversation === conversation.id ? "bg-muted" : ""
                  }`}
                  onClick={() => setSelectedConversation(conversation.id)}
                >
                  <div className="relative">
                    {conversation.type === "groupe" ? (
                      <div className="w-10 h-10 bg-primary/10 rounded-full flex items-center justify-center">
                        <Users className="h-5 w-5 text-primary" />
                      </div>
                    ) : (
                      <Avatar className="w-10 h-10">
                        <AvatarFallback>
                          {(() => {
                            const otherUser = conversation.participants.find(id => id !== "current_user");
                            const user = getUser(otherUser || "");
                            return user ? `${user.prenom[0]}${user.nom[0]}` : "?";
                          })()}
                        </AvatarFallback>
                      </Avatar>
                    )}
                    {conversation.type === "prive" && (() => {
                      const otherUser = conversation.participants.find(id => id !== "current_user");
                      const user = getUser(otherUser || "");
                      return user ? (
                        <div className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-background ${getStatusColor(user.statut)}`} />
                      ) : null;
                    })()}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <p className="font-medium text-sm truncate">
                        {getConversationName(conversation)}
                      </p>
                      {conversation.messages_non_lus > 0 && (
                        <Badge variant="destructive" className="text-xs">
                          {conversation.messages_non_lus}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground truncate">
                      {conversation.type === "groupe" ? `${conversation.participants.length} participants` : "Conversation privée"}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            <Separator />

            <div className="mt-4">
              <p className="text-sm font-medium text-muted-foreground mb-2 px-2">Utilisateurs ({filteredUsers.length})</p>
              {filteredUsers.map((user) => (
                <div
                  key={user.id}
                  className="flex items-center gap-3 p-3 rounded-lg cursor-pointer hover:bg-muted/50"
                  onClick={() => {
                    // Créer ou ouvrir conversation privée
                    const existingConv = conversations.find(c => 
                      c.type === "prive" && c.participants.includes(user.id)
                    );
                    if (existingConv) {
                      setSelectedConversation(existingConv.id);
                    }
                  }}
                >
                  <div className="relative">
                    <Avatar className="w-10 h-10">
                      <AvatarFallback>{user.prenom[0]}{user.nom[0]}</AvatarFallback>
                    </Avatar>
                    <div className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-background ${getStatusColor(user.statut)}`} />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm">{user.prenom} {user.nom}</p>
                    <p className="text-xs text-muted-foreground truncate">{user.poste}</p>
                    <p className="text-xs text-muted-foreground">{getStatusLabel(user.statut)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </ScrollArea>
      </div>

      {/* Zone de conversation */}
      <div className="flex-1 flex flex-col">
        {selectedConversation ? (
          <>
            {/* Header conversation */}
            <div className="p-4 border-b bg-background">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {selectedConversationData?.type === "groupe" ? (
                    <div className="w-10 h-10 bg-primary/10 rounded-full flex items-center justify-center">
                      <Users className="h-5 w-5 text-primary" />
                    </div>
                  ) : (
                    <Avatar className="w-10 h-10">
                      <AvatarFallback>
                        {(() => {
                          const otherUser = selectedConversationData?.participants.find(id => id !== "current_user");
                          const user = getUser(otherUser || "");
                          return user ? `${user.prenom[0]}${user.nom[0]}` : "?";
                        })()}
                      </AvatarFallback>
                    </Avatar>
                  )}
                  
                  <div>
                    <h3 className="font-semibold">
                      {selectedConversationData ? getConversationName(selectedConversationData) : ""}
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      {selectedConversationData?.type === "groupe" 
                        ? `${selectedConversationData.participants.length} participants`
                        : "En ligne"
                      }
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="ghost">
                    <Phone className="h-4 w-4" />
                  </Button>
                  <Button size="sm" variant="ghost">
                    <Video className="h-4 w-4" />
                  </Button>
                  <Button size="sm" variant="ghost">
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>

            {/* Messages */}
            <ScrollArea className="flex-1 p-4">
              <div className="space-y-4">
                {conversationMessages.map((message) => {
                  const isOwn = message.expediteur_id === "current_user";
                  const expediteur = getUser(message.expediteur_id);
                  
                  return (
                    <div
                      key={message.id}
                      className={`flex ${isOwn ? "justify-end" : "justify-start"}`}
                    >
                      <div className={`flex gap-2 max-w-[70%] ${isOwn ? "flex-row-reverse" : ""}`}>
                        {!isOwn && (
                          <Avatar className="w-8 h-8 mt-auto">
                            <AvatarFallback className="text-xs">
                              {expediteur ? `${expediteur.prenom[0]}${expediteur.nom[0]}` : "?"}
                            </AvatarFallback>
                          </Avatar>
                        )}
                        
                        <div className={`rounded-lg p-3 ${
                          isOwn 
                            ? "bg-primary text-primary-foreground" 
                            : "bg-muted"
                        }`}>
                          {!isOwn && (
                            <p className="text-xs font-medium mb-1">
                              {expediteur ? `${expediteur.prenom} ${expediteur.nom}` : "Utilisateur"}
                            </p>
                          )}
                          <p className="text-sm">{message.contenu}</p>
                          <p className={`text-xs mt-1 ${
                            isOwn ? "text-primary-foreground/70" : "text-muted-foreground"
                          }`}>
                            {message.date_envoi.toLocaleTimeString('fr-FR', { 
                              hour: '2-digit', 
                              minute: '2-digit' 
                            })}
                          </p>
                        </div>
                      </div>
                    </div>
                  );
                })}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>

            {/* Zone de saisie */}
            <div className="p-4 border-t bg-background">
              <div className="flex items-center gap-2">
                <Button size="sm" variant="ghost">
                  <Paperclip className="h-4 w-4" />
                </Button>
                <Button size="sm" variant="ghost">
                  <Smile className="h-4 w-4" />
                </Button>
                <Input
                  placeholder="Tapez votre message..."
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && sendMessage()}
                  className="flex-1"
                />
                <Button onClick={sendMessage} disabled={!messageText.trim()}>
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-center">
            <div>
              <Users className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-semibold mb-2">Sélectionnez une conversation</h3>
              <p className="text-muted-foreground">
                Choisissez une conversation ou un utilisateur pour commencer à discuter
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}